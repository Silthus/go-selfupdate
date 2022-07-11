/*
Copyright © 2022 Michael Reichenbach <me@silthus.net>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/silthus/go-selfupdate/selfupdate"
	"github.com/spf13/cobra"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
)

var version = "dev"

var (
	appPath    string
	appVersion string
	keyFile    string
	outputDir  string
	platform   string
	privateKey *rsa.PrivateKey
)

func main() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Version: version,
	Use:     "go-selfupdate <binary-path> <version>",
	Short:   "Generates the needed update files for the go-selfupdate library.",
	Long: `Put the generated files somewhere on a web server where they can be reached by your clients.

For example to create an update for a single OS distribution:
go-selfupdate my-cli.exe 1.0.0

You can also point it to a directory containing multiple binaries in the following format
and it will generate release files for all operating systems: <goos>-<goarch>.<ext>

go-selfupdate ./build/ 1.0.0`,
	Args: cobra.ExactArgs(2),
	PreRunE: func(cmd *cobra.Command, args []string) (err error) {
		appPath = args[0]
		appVersion = args[1]

		privateKey, err = validatePrivateKey()

		if err = createBuildDir(); err != nil {
			return fmt.Errorf("failed to create output dir: %w", err)
		}

		return err
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		version := selfupdate.Info{
			Version: appVersion,
		}

		fileInfo, err := os.Stat(args[0])
		if err != nil {
			return fmt.Errorf("failed to open binary location: %w", err)
		}

		if fileInfo.IsDir() {
			files, err := ioutil.ReadDir(appPath)
			if err == nil {
				for _, file := range files {
					selfupdate.CreateUpdate(version, filepath.Join(appPath, file.Name()), file.Name(), outputDir, privateKey)
				}
			}
		} else {
			selfupdate.CreateUpdate(version, appPath, platform, outputDir, privateKey)
		}

		return nil
	},
}

func init() {
	rootCmd.Flags().StringVarP(&keyFile, "key", "k", "", "private key file for singing the binaries")
	rootCmd.Flags().StringVarP(&outputDir, "output", "o", "public", "output dir for the generated release files")
	rootCmd.Flags().StringVarP(&platform, "platform", "p", defaultPlatform(), "platform to generate release for")
}

func validatePrivateKey() (key *rsa.PrivateKey, err error) {
	if keyFile == "" {
		return nil, nil
	}

	content, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}

	if key, err = parseRsaPrivateKeyFromPemStr(content); err != nil {
		return nil, fmt.Errorf("failed to parse private key %s: %w", keyFile, err)
	}

	return key, nil
}

func parseRsaPrivateKeyFromPemStr(privPEM []byte) (*rsa.PrivateKey, error) {
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

func createBuildDir() error {
	return os.MkdirAll(outputDir, 0755)
}

func defaultPlatform() string {
	goos := os.Getenv("GOOS")
	goarch := os.Getenv("GOARCH")
	if goos != "" && goarch != "" {
		return goos + "-" + goarch
	} else {
		return runtime.GOOS + "-" + runtime.GOARCH
	}
}
