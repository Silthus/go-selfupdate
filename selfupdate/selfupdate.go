// Update protocol:
//
//   GET hk.heroku.com/hk/linux-amd64.json
//
//   200 ok
//   {
//       "Version": "2",
//       "Sha256": "..." // base64
//   }
//
// then
//
//   GET hkpatch.s3.amazonaws.com/hk/1/2/linux-amd64
//
//   200 ok
//   [bsdiff data]
//
// or
//
//   GET hkdist.s3.amazonaws.com/hk/2/linux-amd64.gz
//
//   200 ok
//   [gzipped executable data]
//
//
package selfupdate

import (
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/kardianos/osext"
	"github.com/kr/binarydist"
	"gopkg.in/inconshreveable/go-update.v0"
)

const (
	upcktimePath = "cktime"
	plat         = runtime.GOOS + "-" + runtime.GOARCH
)

const devValidTime = 7 * 24 * time.Hour

var ErrHashMismatch = errors.New("new file hash mismatch after patch")
var ErrSignatureMismatch = errors.New("new file signature mismatch after patch")
var up = update.New()
var defaultHTTPRequester = HTTPRequester{}

// Updater is the configuration and runtime data for doing an update.
//
// Note that ApiURL, BinURL and DiffURL should have the same value if all files are available at the same location.
//
// Example:
//
//  updater := &selfupdate.Updater{
//  	CurrentVersion: version,
//  	ApiURL:         "http://updates.yourdomain.com/",
//  	BinURL:         "http://updates.yourdownmain.com/",
//  	DiffURL:        "http://updates.yourdomain.com/",
//  	Dir:            "update/",
//  	CmdName:        "myapp", // app name
//  }
//  if updater != nil {
//  	go updater.BackgroundRun()
//  }
type Updater struct {
	CurrentVersion string         // Currently running version.
	ApiURL         string         // Base URL for API requests (json files).
	CmdName        string         // Command name is appended to the ApiURL like http://apiurl/CmdName/. This represents one binary.
	BinURL         string         // Base URL for full binary downloads.
	DiffURL        string         // Base URL for diff downloads.
	Dir            string         // Directory to store selfupdate state.
	ForceCheck     bool           // Check for update regardless of cktime timestamp
	CheckTime      int            // Time in hours before next check
	RandomizeTime  int            // Time in hours to randomize with CheckTime
	Requester      Requester      //Optional parameter to override existing http request handler
	PublicKey      *rsa.PublicKey // Optional parameter to check signature in the update. If a key is set any binary must be checked with supplied Signature hash of API
	Target         string         // Optional parameter to specify binary to update. Set to current executable if not specified
}

func (u *Updater) getTargetAbsoluteDir() string {
	if u.Target == "" {
		filename, err := osext.Executable()
		if err != nil {
			panic(err)
		}
		return filename
	}
	return u.Target
}

func (u *Updater) getExecRelativeDir(dir string) string {
	filename := u.getTargetAbsoluteDir()
	path := filepath.Join(filepath.Dir(filename), dir)
	return path
}

// BackgroundRun starts the update check and apply cycle.
// A new applied version is returned.
func (u *Updater) BackgroundRun() (Info, error) {
	if err := os.MkdirAll(u.getExecRelativeDir(u.Dir), 0777); err != nil {
		// fail
		return Info{}, err
	}
	if u.WantUpdate() {
		if err := up.CanUpdate(); err != nil {
			// fail
			return Info{}, err
		}

		u.SetUpdateTime()
		return u.Update()
	}
	return Info{}, nil
}

// WantUpdate returns boolean designating if an update is desired
func (u *Updater) WantUpdate() bool {
	if u.CurrentVersion == "dev" || (!u.ForceCheck && u.NextUpdate().After(time.Now())) {
		return false
	}

	return true
}

// NextUpdate returns the next time update should be checked
func (u *Updater) NextUpdate() time.Time {
	path := u.getExecRelativeDir(u.Dir + upcktimePath)
	nextTime := readTime(path)

	return nextTime
}

// SetUpdateTime writes the next update time to the state file
func (u *Updater) SetUpdateTime() bool {
	path := u.getExecRelativeDir(u.Dir + upcktimePath)
	wait := time.Duration(u.CheckTime) * time.Hour
	// Add 1 to random time since max is not included
	waitrand := time.Duration(rand.Intn(u.RandomizeTime+1)) * time.Hour

	return writeTime(path, time.Now().Add(wait+waitrand))
}

// ClearUpdateState writes current time to state file
func (u *Updater) ClearUpdateState() {
	path := u.getExecRelativeDir(u.Dir + upcktimePath)
	os.Remove(path)
}

// UpdateAvailable checks if update is available and returns version
func (u *Updater) UpdateAvailable() (string, error) {
	path := u.getTargetAbsoluteDir()
	old, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer old.Close()

	info, err := u.fetchInfo()
	if err != nil {
		return "", err
	}
	if info.Version == u.CurrentVersion {
		return "", nil
	} else {
		return info.Version, nil
	}
}

func (u *Updater) GetNextVersion() (Info, error) {
	return u.fetchInfo()
}

// Update initiates the self update process
func (u *Updater) Update() (Info, error) {
	path := u.getTargetAbsoluteDir()
	old, err := os.Open(path)
	if err != nil {
		return Info{}, err
	}
	defer old.Close()

	info, err := u.fetchInfo()
	if err != nil {
		return Info{}, err
	}
	if info.Version == "" {
		// No Update available
		return Info{}, nil
	}
	if info.Version == u.CurrentVersion {
		return Info{}, nil
	}
	if u.PublicKey != nil {
		if info.Signature == nil {
			return Info{}, fmt.Errorf("update: configured with public key but version info had no signature")
		}
	}
	bin, err := u.fetchAndVerifyPatch(info, old)
	if err != nil {
		if err == ErrHashMismatch {
			log.Println("update: hash mismatch from patched binary")
		} else {
			if u.DiffURL != "" {
				log.Println("update: error patching binary,", err)
			}
		}

		bin, err = u.fetchAndVerifyFullBin(info)
		if err != nil {
			if err == ErrHashMismatch {
				log.Println("update: hash mismatch from full binary")
			} else {
				log.Println("update: error fetching full binary,", err)
			}
			return Info{}, err
		}
	}

	// close the old binary before installing because on windows
	// it can't be renamed if a handle to the file is still open
	old.Close()

	err, errRecover := up.FromStream(bytes.NewBuffer(bin))
	if errRecover != nil {
		return Info{}, fmt.Errorf("update and recovery errors: %q %q", err, errRecover)
	}
	if err != nil {
		return Info{}, err
	}
	return info, nil
}

func (u *Updater) fetchInfo() (Info, error) {
	r, err := u.fetch(u.ApiURL + url.QueryEscape(u.CmdName) + "/" + url.QueryEscape(plat) + ".json")
	if err != nil {
		return Info{}, err
	}
	defer r.Close()
	info := Info{}
	err = json.NewDecoder(r).Decode(&info)
	if err != nil {
		return Info{}, err
	}
	if info.Version != "" && len(info.Sha256) != sha256.Size {
		return Info{}, fmt.Errorf("bad cmd hash in info. Expected %v got %v", sha256.Size, len(info.Sha256))
	}
	return info, nil
}

func (u *Updater) fetchAndVerifyPatch(info Info, old io.Reader) ([]byte, error) {
	bin, err := u.fetchAndApplyPatch(info, old)
	if err != nil {
		return nil, err
	}
	if !verifySha(bin, info.Sha256) {
		return nil, ErrHashMismatch
	}
	if !verifySignature(u.PublicKey, bin, info.Signature) {
		return nil, ErrSignatureMismatch
	}
	return bin, nil
}

func (u *Updater) fetchAndApplyPatch(info Info, old io.Reader) ([]byte, error) {
	r, err := u.fetch(u.DiffURL + url.QueryEscape(u.CmdName) + "/" + url.QueryEscape(u.CurrentVersion) + "/" + url.QueryEscape(info.Version) + "/" + url.QueryEscape(plat))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	var buf bytes.Buffer
	err = binarydist.Patch(old, &buf, r)
	return buf.Bytes(), err
}

func (u *Updater) fetchAndVerifyFullBin(info Info) ([]byte, error) {
	bin, err := u.fetchBin(info)
	if err != nil {
		return nil, err
	}
	verified := verifySha(bin, info.Sha256)
	if !verified {
		return nil, ErrHashMismatch
	}
	if !verifySignature(u.PublicKey, bin, info.Signature) {
		return nil, ErrSignatureMismatch
	}
	return bin, nil
}

func (u *Updater) fetchBin(info Info) ([]byte, error) {
	r, err := u.fetch(u.BinURL + url.QueryEscape(u.CmdName) + "/" + url.QueryEscape(info.Version) + "/" + url.QueryEscape(plat) + ".gz")
	if err != nil {
		return nil, err
	}
	defer r.Close()
	buf := new(bytes.Buffer)
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	if _, err = io.Copy(buf, gz); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (u *Updater) fetch(url string) (io.ReadCloser, error) {
	if u.Requester == nil {
		return defaultHTTPRequester.Fetch(url)
	}

	readCloser, err := u.Requester.Fetch(url)
	if err != nil {
		return nil, err
	}

	if readCloser == nil {
		return nil, fmt.Errorf("Fetch was expected to return non-nil ReadCloser")
	}

	return readCloser, nil
}

func readTime(path string) time.Time {
	p, err := ioutil.ReadFile(path)
	if os.IsNotExist(err) {
		return time.Time{}
	}
	if err != nil {
		return time.Now().Add(1000 * time.Hour)
	}
	t, err := time.Parse(time.RFC3339, string(p))
	if err != nil {
		return time.Now().Add(1000 * time.Hour)
	}
	return t
}

func verifySha(bin []byte, sha []byte) bool {
	h := sha256.New()
	h.Write(bin)
	return bytes.Equal(h.Sum(nil), sha)
}

func verifySignature(pk *rsa.PublicKey, bin []byte, sig []byte) bool {
	if pk == nil {
		return true
	}
	h := sha256.New()
	h.Write(bin)
	if err := rsa.VerifyPKCS1v15(pk, crypto.SHA256, h.Sum(nil), sig); err != nil {
		return false
	}
	return true
}

func writeTime(path string, t time.Time) bool {
	return ioutil.WriteFile(path, []byte(t.Format(time.RFC3339)), 0644) == nil
}
