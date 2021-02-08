package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"io/ioutil"
	"log"

	"github.com/sanbornm/go-selfupdate/selfupdate"
)

var version string

var updater = &selfupdate.Updater{
	CurrentVersion: version,                  // Manually update the const, or set it using `go build -ldflags="-X main.VERSION=<newver>" -o hello-updater src/hello-updater/main.go`
	ApiURL:         "http://localhost:8080/", // The server hosting `$CmdName/$GOOS-$ARCH.json` which contains the checksum for the binary
	BinURL:         "http://localhost:8080/", // The server hosting the zip file containing the binary application which is a fallback for the patch method
	DiffURL:        "http://localhost:8080/", // The server hosting the binary patch diff for incremental updates
	Dir:            "update/",                // The directory created by the app when run which stores the cktime file
	CmdName:        "hello-updater",          // The app name which is appended to the ApiURL to look for an update
	ForceCheck:     true,                     // For this example, always check for an update unless the version is "dev"
}

func ParseRsaPublicKeyFromPemStr(pubPEM []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break // fall through
	}
	return nil, errors.New("Key type is not RSA")
}

func main() {
	keyFileFlag := flag.String("k", "", "Public key to use for verifying the binary")
	flag.Parse()
	if *keyFileFlag != "" {
		content, err := ioutil.ReadFile(*keyFileFlag)
		if err != nil {
			panic(err)
		}
		pub, err := ParseRsaPublicKeyFromPemStr(content)
		if err != nil {
			panic(err)
		}
		updater.PublicKey = pub
	}
	log.Printf("Hello world I am currently version %v", updater.CurrentVersion)
	if updater.PublicKey != nil {
		log.Println("I am crypto secure")
	}
	newV, err := updater.BackgroundRun()
	if err != nil {
		panic(err)
	}
	if newV.Version != "" {
		log.Printf("Next run, I should be %v", newV.Version)
	} else {
		log.Printf("No update applied. I still should be %v next run", updater.CurrentVersion)
	}
}
