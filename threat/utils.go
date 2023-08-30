// Copyright Dwi Siswanto and/or licensed to Dwi Siswanto under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.
// See the LICENSE-ELv2 file in the project root for more information.

package threat

import (
	"fmt"

	"path/filepath"
)

// String returns the string representation of a Threat value
func (t Threat) String() string {
	if s, ok := str[t]; ok {
		return s
	}

	return ""
}

// Filename returns the file name representation of a Threat value
//
// If `full` is true, it returns the `full` file path by calling the location
// function and joining it with the corresponding file name.
// If `full` is false, it returns only the file name without the path.
// It returns an error if `full` is true but the location function returns an
// error or if the corresponding file name cannot be found for the Threat value.
func (t Threat) Filename(full bool) (string, error) {
	var path string
	var err error

	if full {
		path, err = location()
		if err != nil {
			return "", err
		}
	} else {
		path = ""
	}

	if file, ok := file[t]; ok {
		return filepath.Join(path, file), nil
	}

	return "", fmt.Errorf(errFilepath, t.String())
}

// List returns a slice of all Threat type categories
func List() []Threat {
	// Pre-allocate a slice of Threat with the str (size)-2
	threats := make([]Threat, len(str)-2)

	i := 0
	for t := range str {
		// Skip if it is undefined or custom
		switch t {
		case Undefined, Custom:
			continue
		}

		// Set the value in the slice using the index operator
		threats[i] = t
		i++
	}

	return threats
}
