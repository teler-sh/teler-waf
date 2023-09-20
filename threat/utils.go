// Licensed to Dwi Siswanto under one or more agreements.
// Dwi Siswanto licenses this file to you under the Apache 2.0 License.
// See the LICENSE-APACHE file in the project root for more information.

package threat

import (
	"fmt"

	"path/filepath"

	"github.com/bitfield/script"
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
		path, err = Location()
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

// Count returns the number of datasets from a Threat
func (t Threat) Count() (int, error) {
	if int8(t) <= 0 {
		return 0, nil
	}

	path, err := t.Filename(true)
	if err != nil {
		return 0, err
	}

	file := script.File(path)

	switch t {
	case CommonWebAttack:
		return file.JQ(".filters[].id").CountLines()
	case CVE:
		return file.JQ(".templates[].id").CountLines()
	}

	return file.CountLines()
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
