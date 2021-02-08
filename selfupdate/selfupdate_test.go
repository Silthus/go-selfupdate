package selfupdate

import (
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/kardianos/osext"
	"github.com/sanbornm/go-selfupdate/selfupdate/mocks"
)

var testHash = sha256.New()
var tempDir = os.TempDir()

func TestUpdaterFetchMustReturnNonNilReaderCloser(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mr := mocks.NewMockRequester(ctrl)
	mr.EXPECT().Fetch(fmt.Sprintf("http://api.updates.yourdomain.com/myapp/%v.json", plat)).Return(nil, nil).Times(1)

	updater := createUpdater(mr)
	_, err := updater.BackgroundRun()

	if err != nil {
		equals(t, "Fetch was expected to return non-nil ReadCloser", err.Error())
	} else {
		t.Log("Expected an error")
		t.Fail()
	}
}

func TestUpdaterWithEmptyPayloadNoErrorNoUpdate(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mr := mocks.NewMockRequester(ctrl)
	mr.EXPECT().Fetch(fmt.Sprintf("http://api.updates.yourdomain.com/myapp/%v.json", plat)).Return(newTestReaderCloser("{}"), nil).Times(1)
	mr.EXPECT().Fetch(gomock.Any()).Times(0)

	updater := createUpdater(mr)
	updater.CheckTime = 24
	updater.RandomizeTime = 24

	_, err := updater.BackgroundRun()
	if err != nil {
		t.Errorf("Error occurred: %#v", err)
	}
}

func TestUpdaterWithNewVersionAndMissingBinaryReturnsError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mr := mocks.NewMockRequester(ctrl)
	h := sha256.New()
	h.Write([]byte("Test"))
	c := Info{Version: "1.3", Sha256: h.Sum(nil)}

	b, err := json.MarshalIndent(c, "", "    ")
	mr.EXPECT().Fetch(fmt.Sprintf("http://api.updates.yourdomain.com/myapp/%v.json", plat)).Return(newTestReaderCloser(string(b)), nil).Times(1)
	mr.EXPECT().Fetch(fmt.Sprintf("http://diff.updates.yourdomain.com/myapp/1.2/1.3/%v", plat)).Return(newTestReaderCloser("{}"), fmt.Errorf("Bad status code on diff: 404")).Times(1)
	mr.EXPECT().Fetch(fmt.Sprintf("http://bin.updates.yourdownmain.com/myapp/1.3/%v.gz", plat)).Return(newTestReaderCloser("{}"), fmt.Errorf("Bad status code on binary: 404")).Times(1)
	mr.EXPECT().Fetch(gomock.Any()).Times(0)

	updater := createUpdater(mr)
	updater.ForceCheck = true

	_, err = updater.BackgroundRun()
	if err != nil {
		equals(t, "Bad status code on binary: 404", err.Error())
	} else {
		t.Log("Expected an error")
		t.Fail()
	}
}

func TestUpdaterCheckTime(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mr := mocks.NewMockRequester(ctrl)
	mr.EXPECT().Fetch(fmt.Sprintf("http://api.updates.yourdomain.com/myapp/%v.json", plat)).Return(newTestReaderCloser("{}"), nil).Times(4)
	mr.EXPECT().Fetch(gomock.Any()).Times(0) // no additional calls

	// Run test with various time
	runTestTimeChecks(t, mr, 0, 0, false)
	runTestTimeChecks(t, mr, 0, 5, true)
	runTestTimeChecks(t, mr, 1, 0, true)
	runTestTimeChecks(t, mr, 100, 100, true)
}

func TestUpdaterWithSigningKeyErrorOnNoSignature(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mr := mocks.NewMockRequester(ctrl)
	h := sha256.New()
	h.Write([]byte("Test"))
	c := Info{Version: "1.3", Sha256: h.Sum(nil)}

	b, err := json.MarshalIndent(c, "", "    ")
	mr.EXPECT().Fetch(fmt.Sprintf("http://api.updates.yourdomain.com/myapp/%v.json", plat)).Return(newTestReaderCloser(string(b)), nil).Times(1)
	mr.EXPECT().Fetch(gomock.Any()).Times(0)

	_, updater := createUpdaterWithSigningKey("", mr)
	updater.ForceCheck = true

	_, err = updater.BackgroundRun()
	if err != nil {
		equals(t, "update: configured with public key but version info had no signature", err.Error())
	} else {
		t.Log("Expected an error")
		t.Fail()
	}
}

func TestUpdaterWithSigningKeyErrorOnSignatureMismatch(t *testing.T) {
	// Given binary and wrong
	binDir, err := osext.Executable()
	fmt.Printf("Selfupdate on binary: %v\n", binDir)
	fmt.Printf("Testdir is: %v\n", tempDir)
	goldenBeforePath := fmt.Sprintf("%v%v", tempDir, "golden_before")
	copy(binDir, goldenBeforePath)

	fmt.Printf("Written: %v\n", goldenBeforePath)
	os.MkdirAll(tempDir+"update", 0700)
	CreateUpdate(Info{Version: "1.2"}, goldenBeforePath, plat, tempDir+"update", nil)
	CreateUpdate(Info{Version: "1.3"}, goldenBeforePath, plat, tempDir+"update", nil)

	// copy("testdata/sample.patch", tempDir+"update"+"/patch")
	file := mustOpen(goldenBeforePath)
	// file := mustWriteRandFile(tempDir+"update"+"/patch", 100, 1)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mr := mocks.NewMockRequester(ctrl)
	wrongHash := sha256.New()
	wrongHash.Write([]byte("Test"))
	sum := GenerateSha256(goldenBeforePath)
	pk, updater := createUpdaterWithSigningKey(goldenBeforePath, mr)
	signature, err := rsa.SignPKCS1v15(rand.Reader, pk, crypto.SHA256, wrongHash.Sum(nil))
	c := Info{Version: "1.3", Sha256: sum, Signature: signature}

	b, err := json.MarshalIndent(c, "", "    ")
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	// f := []byte{0x01, 0x02}
	if err != nil {
		panic(err)
	}
	// io.Copy(w, file)
	bin, err := ioutil.ReadAll(file)
	w.Write(bin)
	w.Close() // You must close this first to flush the bytes to the buffer.

	mr.EXPECT().Fetch(fmt.Sprintf("http://api.updates.yourdomain.com/myapp/%v.json", plat)).Return(newTestReaderCloser(string(b)), nil).Times(1)
	mr.EXPECT().Fetch(fmt.Sprintf("http://diff.updates.yourdomain.com/myapp/1.2/1.3/%v", plat)).Return(newTestReaderCloser("{}"), errors.New("404")).Times(1)
	mr.EXPECT().Fetch(fmt.Sprintf("http://bin.updates.yourdownmain.com/myapp/1.3/%v.gz", plat)).Return(ioutil.NopCloser(&buf), nil).Times(1)
	mr.EXPECT().Fetch(gomock.Any()).Times(0)

	_, err = updater.Update()
	if err != nil {
		equals(t, "new file signature mismatch after patch", err.Error())
	} else {
		t.Log("Expected an error")
		t.Fail()
	}
}

// Helper function to run check time tests
func runTestTimeChecks(t *testing.T, mr Requester, checkTime int, randomizeTime int, expectUpdate bool) {
	updater := createUpdater(mr)
	updater.ClearUpdateState()
	updater.CheckTime = checkTime
	updater.RandomizeTime = randomizeTime

	updater.BackgroundRun()

	if updater.WantUpdate() == expectUpdate {
		t.Errorf("WantUpdate returned %v; want %v", updater.WantUpdate(), expectUpdate)
	}

	maxHrs := time.Duration(updater.CheckTime+updater.RandomizeTime) * time.Hour
	maxTime := time.Now().Add(maxHrs)

	if !updater.NextUpdate().Before(maxTime) {
		t.Errorf("NextUpdate should less than %s hrs (CheckTime + RandomizeTime) from now; now %s; next update %s", maxHrs, time.Now(), updater.NextUpdate())
	}

	if maxHrs > 0 && !updater.NextUpdate().After(time.Now()) {
		t.Errorf("NextUpdate should be after now")
	}
}

func TestUpdaterWithEmptyPayloadNoErrorNoUpdateEscapedPath(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mr := mocks.NewMockRequester(ctrl)
	basePath := "http://api.updates.yourdomain.com/myapp%2Bfoo"
	mr.EXPECT().Fetch(fmt.Sprintf("%v/%v.json", basePath, plat)).Return(newTestReaderCloser("{}"), nil).Times(1)
	mr.EXPECT().Fetch(gomock.Any()).Times(0) // no additional calls

	updater := createUpdaterWithEscapedCharacters(mr)
	updater.ForceCheck = true

	_, err := updater.BackgroundRun()
	if err != nil {
		t.Errorf("Error occurred: %#v", err)
	}
}

func createUpdater(mr Requester) *Updater {
	return &Updater{
		CurrentVersion: "1.2",
		ApiURL:         "http://api.updates.yourdomain.com/",
		BinURL:         "http://bin.updates.yourdownmain.com/",
		DiffURL:        "http://diff.updates.yourdomain.com/",
		Dir:            tempDir + "update/",
		CmdName:        "myapp", // app name
		Requester:      mr,
	}
}

func createUpdaterWithEscapedCharacters(mr Requester) *Updater {
	return &Updater{
		CurrentVersion: "1.2+foobar",
		ApiURL:         "http://api.updates.yourdomain.com/",
		BinURL:         "http://bin.updates.yourdownmain.com/",
		DiffURL:        "http://diff.updates.yourdomain.com/",
		Dir:            tempDir + "update/",
		CmdName:        "myapp+foo", // app name
		Requester:      mr,
	}
}

func createUpdaterWithSigningKey(binaryPath string, mr Requester) (*rsa.PrivateKey, *Updater) {
	// generate key
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("Cannot generate RSA key\n")
		os.Exit(1)
	}
	publickey := &privatekey.PublicKey

	// dump private key to file
	// var privateKeyBytes []byte = x509.MarshalPKCS1PrivateKey(privatekey)
	// privateKeyBlock := &pem.Block{
	// 	Type:  "RSA PRIVATE KEY",
	// 	Bytes: privateKeyBytes,
	// }
	// privatePem, err := os.Create("private.pem")
	// if err != nil {
	// 	fmt.Printf("error when create private.pem: %s \n", err)
	// 	return nil
	// }
	// err = pem.Encode(privatePem, privateKeyBlock)
	// if err != nil {
	// 	fmt.Printf("error when encode private pem: %s \n", err)
	// 	return nil
	// }

	// dump public key to file
	// publicKeyBytes, err := x509.MarshalPKIXPublicKey(publickey)
	// if err != nil {
	// 	fmt.Printf("error when dumping publickey: %s \n", err)
	// 	return nil
	// }
	// publicKeyBlock := &pem.Block{
	// 	Type:  "PUBLIC KEY",
	// 	Bytes: publicKeyBytes,
	// }
	// publicPem, err := os.Create("public.pem")
	// if err != nil {
	// 	fmt.Printf("error when create public.pem: %s \n", err)
	// 	return nil
	// }
	// err = pem.Encode(publicPem, publicKeyBlock)
	// if err != nil {
	// 	fmt.Printf("error when encode public pem: %s \n", err)
	// 	return nil
	// }
	return privatekey, &Updater{
		CurrentVersion: "1.2",
		ApiURL:         "http://api.updates.yourdomain.com/",
		BinURL:         "http://bin.updates.yourdownmain.com/",
		DiffURL:        "http://diff.updates.yourdomain.com/",
		Dir:            "update/",
		CmdName:        "myapp", // app name
		Requester:      mr,
		PublicKey:      publickey,
		Target:         binaryPath,
	}
}

func equals(t *testing.T, expected, actual interface{}) {
	if expected != actual {
		panic(fmt.Sprintf("Expected: %#v %#v\n", expected, actual))
	}
}

func copy(src, dst string) (int64, error) {
	if strings.HasSuffix(dst, "/") {
		panic("cannot copy to directory path")
	}
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return 0, err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer destination.Close()
	nBytes, err := io.Copy(destination, source)
	return nBytes, err
}

func mustWriteRandFile(path string, size int, seed int64) *os.File {
	p := make([]byte, size)

	_, err := rand.Read(p)
	if err != nil {
		panic(err)
	}

	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}

	_, err = f.Write(p)
	if err != nil {
		panic(err)
	}

	_, err = f.Seek(0, 0)
	if err != nil {
		panic(err)
	}

	return f
}

func mustOpen(path string) *os.File {
	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}

	return f
}

type testReadCloser struct {
	buffer *bytes.Buffer
}

func newTestReaderCloser(payload string) io.ReadCloser {
	return &testReadCloser{buffer: bytes.NewBufferString(payload)}
}

func (trc *testReadCloser) Read(p []byte) (n int, err error) {
	return trc.buffer.Read(p)
}

func (trc *testReadCloser) Close() error {
	return nil
}
