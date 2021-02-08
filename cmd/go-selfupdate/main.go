package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"

	"github.com/segfault16/go-selfupdate/selfupdate"
)

var version, genDir string

func printUsage() {
	fmt.Println("")
	fmt.Println("Positional arguments:")
	fmt.Println("\tSingle platform: go-selfupdate myapp 1.2")
	fmt.Println("\tCross platform: go-selfupdate /tmp/mybinares/ 1.2")
}

func createBuildDir() {
	os.MkdirAll(genDir, 0755)
}

func ParseRsaPrivateKeyFromPemStr(privPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privPEM)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func main() {
	outputDirFlag := flag.String("o", "public", "Output directory for writing updates")
	keyFileFlag := flag.String("k", "", "Private key to use for signing the binary")

	var defaultPlatform string
	goos := os.Getenv("GOOS")
	goarch := os.Getenv("GOARCH")
	if goos != "" && goarch != "" {
		defaultPlatform = goos + "-" + goarch
	} else {
		defaultPlatform = runtime.GOOS + "-" + runtime.GOARCH
	}
	platformFlag := flag.String("platform", defaultPlatform,
		"Target platform in the form OS-ARCH. Defaults to running os/arch or the combination of the environment variables GOOS and GOARCH if both are set.")

	flag.Parse()
	if flag.NArg() < 2 {
		flag.Usage()
		printUsage()
		os.Exit(0)
	}

	platform := *platformFlag
	appPath := flag.Arg(0)
	version = flag.Arg(1)
	genDir = *outputDirFlag
	var pk *rsa.PrivateKey
	if keyFileFlag != nil {
		content, err := ioutil.ReadFile(*keyFileFlag)
		if err != nil {
			panic(err)
		}
		pk, err = ParseRsaPrivateKeyFromPemStr(content)
	}

	createBuildDir()
	version := selfupdate.Info{
		Version: version,
	}

	// If dir is given create update for each file
	fi, err := os.Stat(appPath)
	if err != nil {
		panic(err)
	}

	if fi.IsDir() {
		files, err := ioutil.ReadDir(appPath)
		if err == nil {
			for _, file := range files {
				selfupdate.CreateUpdate(version, filepath.Join(appPath, file.Name()), file.Name(), genDir, pk)
			}
			os.Exit(0)
		}
	}

	selfupdate.CreateUpdate(version, appPath, platform, genDir, pk)
}
