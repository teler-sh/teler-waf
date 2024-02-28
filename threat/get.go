// Licensed to Dwi Siswanto under one or more agreements.
// Dwi Siswanto licenses this file to you under the Apache 2.0 License.
// See the LICENSE-APACHE file in the project root for more information.

package threat

import (
	"fmt"
	"os"
	"time"

	"path/filepath"

	"github.com/hashicorp/go-getter"
	"github.com/otiai10/copy"
)

// Get retrieves all the teler threat datasets.
//
// It returns an error if there was an issue when retrieving the datasets.
func Get() error {
	// Get the destination location for the datasets
	dst, err := Location()
	if err != nil {
		// If there was an error getting the location, return the error
		return err
	}

	// Delete existing threat datasets
	if err = os.RemoveAll(dst); err != nil {
		// If there was an error deleting the datasets, return the error
		return err
	}

	// Create the destination directory if it doesn't exist
	err = os.MkdirAll(dst, 0755)
	if err != nil {
		// If there was an error creating the directory, return the error
		return err
	}

	// Downloading teler-resources from local, fallback to repo
	if err := getLocal(); err != nil {
		// Downloading from repo
		err = getter.Get(dst, fmt.Sprintf("%s?%s", DbURL, dbQuery))
		if err != nil {
			return err
		}

		tmpDst, err := TmpLocation()
		if err != nil {
			return err
		}

		// Copy the resources from the cache dir to the temporary dir
		err = copy.Copy(dst, tmpDst)
		if err != nil {
			return err
		}
	}

	return nil
}

// getLocal fetches the local resources, copies them from a temporary location
// to the cache directory, and verifies the checksum of the copied resources.
// It returns an error if any step encounters an issue.
func getLocal() error {
	// Get the destination dir where local resources will be copied
	dst, err := Location()
	if err != nil {
		return err
	}

	// Get the temporary dir containing the resources to be copied
	tmpDst, err := TmpLocation()
	if err != nil {
		return err
	}

	// Copy the resources from the temporary dir to the cache dir
	err = copy.Copy(tmpDst, dst)
	if err != nil {
		return err
	}

	// Verify the checksum of the copied resources
	_, err = Verify()

	// Return any error encountered during the process
	return err
}

// tmpLocation generates a temporary directory path based on the current date
// and creates the directory if it doesn't already exist. It returns the
// path of the temporary directory or an error if the creation fails.
func TmpLocation() (string, error) {
	date := time.Now().Format("02012006")
	tmpDir := filepath.Join(os.TempDir(), fmt.Sprintf(tmpDirSuffix, date))

	err := os.MkdirAll(tmpDir, 0755)
	if err != nil && !os.IsExist(err) {
		return "", err
	}

	return tmpDir, nil
}

// Location returns the location of the teler cache directory.
// It returns an error if there was an issue when getting the user cache directory.
func Location() (string, error) {
	// Get the user cache directory using the os.UserCacheDir function
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		// If there was an error getting the user cache directory, return an empty string and the error
		return "", err
	}

	// Return the full path to the teler cache directory by joining the user cache directory and the cache path
	return filepath.Join(cacheDir, cachePath), nil
}

// IsUpdated checks if the threat datasets are up-to-date.
// It returns a boolean value indicating whether the datasets are updated or not,
// and an error if there was an issue when checking the datasets' last modified date.
func IsUpdated() (bool, error) {
	// Initialize the out variable to false
	var out bool

	// Get the location of the threat datasets
	loc, err := Location()
	if err != nil {
		// If there was an error getting the location, return out and the error
		return out, err
	}

	// Get the file info for the directory containing the threat datasets
	dir, err := os.Stat(loc)
	if err != nil {
		// If there was an error getting the file info, return out and the error
		return out, err
	}

	// Set up the layout string for formatting date
	layout := "2006-01-02"

	// Get the last modified date of the datasets in the desired format and current date
	mod := dir.ModTime().Format(layout)
	now := time.Now().Format(layout)

	// Check if the last modified date is equal to the current date
	out = mod == now

	// Return the result and a nil error
	return out, nil
}
