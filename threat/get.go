// Copyright Dwi Siswanto and/or licensed to Dwi Siswanto under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.
// See the LICENSE-ELv2 file in the project root for more information.

package threat

import (
	"fmt"
	"os"
	"time"

	"path/filepath"

	"github.com/hashicorp/go-getter"
)

// Get retrieves all the teler threat datasets.
//
// It returns an error if there was an issue when retrieving the datasets.
func Get() error {
	// Get the destination location for the datasets
	dst, err := location()
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

	// Retrieve the compressed archive DB file from the GitHub repository using go-getter
	err = getter.Get(dst, fmt.Sprintf("%s?%s", DbURL, dbQuery))
	if err != nil {
		// If there was an error retrieving the files, return the error
		return err
	}

	// Return a nil error
	return nil
}

// location returns the location of the teler cache directory.
// It returns an error if there was an issue when getting the user cache directory.
func location() (string, error) {
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
	loc, err := location()
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
