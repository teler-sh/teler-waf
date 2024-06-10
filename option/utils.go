// Licensed to Dwi Siswanto under one or more agreements.
// Dwi Siswanto licenses this file to you under the Apache 2.0 License.
// See the LICENSE-APACHE file in the project root for more information.

package option

import (
	"fmt"
	"os"

	"encoding/json"

	"github.com/teler-sh/teler-waf"
	"gopkg.in/yaml.v3"
)

func readFile(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf(errNotRegularFile, path)
	}

	return os.ReadFile(path)
}

func unmarshalJSONBytes(raw []byte) (teler.Options, error) {
	var opt teler.Options

	// Unmarshal the JSON into the Options struct
	err := json.Unmarshal(raw, &opt)
	return opt, err
}

func unmarshalYAMLBytes(raw []byte) (teler.Options, error) {
	var opt teler.Options

	// Unmarshal the JSON into the Options struct
	err := yaml.Unmarshal(raw, &opt)
	return opt, err
}
