package threat

import (
	"os"

	"io/ioutil"
	"path/filepath"

	"github.com/hashicorp/go-getter"
)

// Get all teler threat datasets
func Get() error {
	dst, err := location()
	if err != nil {
		return err
	}

	// Create the destination directory if it doesn't exist
	err = os.MkdirAll(dst, 0755)
	if err != nil {
		return err
	}

	// Check destination directory if already have threat datasets
	files, err := ioutil.ReadDir(dst)
	if err != nil {
		return err
	}

	if len(files) >= 6 {
		return nil
	}

	// Retrieve the files from the GitHub repository using go-getter
	err = getter.Get(dst, dbURL)
	if err != nil {
		return err
	}

	return nil
}

// Location of teler cache directory
func location() (string, error) {
	// Get user cache directory
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(cacheDir, cachePath), nil
}
