package selfupdate

import (
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/kr/binarydist"
)

type gzReader struct {
	z, r io.ReadCloser
}

func (g *gzReader) Read(p []byte) (int, error) {
	return g.z.Read(p)
}

func (g *gzReader) Close() error {
	g.z.Close()
	return g.r.Close()
}

func newGzReader(r io.ReadCloser) io.ReadCloser {
	var err error
	g := new(gzReader)
	g.r = r
	g.z, err = gzip.NewReader(r)
	if err != nil {
		panic(err)
	}
	return g
}

func GenerateSha256(path string) []byte {
	h := sha256.New()
	b, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println(err)
	}
	h.Write(b)
	sum := h.Sum(nil)
	return sum
	//return base64.URLEncoding.EncodeToString(sum)
}

func CreateUpdate(version Info, path string, platform string, genDir string, pk *rsa.PrivateKey) {
	c := Info{Version: version.Version, Sha256: GenerateSha256(path)}
	if pk != nil {
		sig, err := rsa.SignPKCS1v15(rand.Reader, pk, crypto.SHA256, c.Sha256)
		if err != nil {
			panic(err)
		}
		c.Signature = sig
	}
	b, err := json.MarshalIndent(c, "", "    ")
	if err != nil {
		fmt.Println("error:", err)
	}
	err = ioutil.WriteFile(filepath.Join(genDir, platform+".json"), b, 0755)
	if err != nil {
		panic(err)
	}

	os.MkdirAll(filepath.Join(genDir, version.Version), 0755)

	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	f, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}
	w.Write(f)
	w.Close() // You must close this first to flush the bytes to the buffer.
	err = ioutil.WriteFile(filepath.Join(genDir, version.Version, platform+".gz"), buf.Bytes(), 0755)

	files, err := ioutil.ReadDir(genDir)
	if err != nil {
		fmt.Println(err)
	}

	for _, file := range files {
		if file.IsDir() == false {
			continue
		}
		if file.Name() == version.Version {
			continue
		}

		os.Mkdir(filepath.Join(genDir, file.Name(), version.Version), 0755)

		fName := filepath.Join(genDir, file.Name(), platform+".gz")
		old, err := os.Open(fName)
		if err != nil {
			// Don't have an old release for this os/arch, continue on
			continue
		}

		fName = filepath.Join(genDir, version.Version, platform+".gz")
		newF, err := os.Open(fName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Can't open %s: error: %s\n", fName, err)
			os.Exit(1)
		}

		ar := newGzReader(old)
		defer ar.Close()
		br := newGzReader(newF)
		defer br.Close()
		patch := new(bytes.Buffer)
		if err := binarydist.Diff(ar, br, patch); err != nil {
			panic(err)
		}
		ioutil.WriteFile(filepath.Join(genDir, file.Name(), version.Version, platform), patch.Bytes(), 0755)
	}
}
