package option

import (
	"fmt"
	"os"

	"encoding/json"

	"github.com/kitabisa/teler-waf"
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
	// Unmarshal the JSON into the Options struct
	err := json.Unmarshal(raw, &opt)
	return opt, err
}

func unmarshalYAMLBytes(raw []byte) (teler.Options, error) {
	// Unmarshal the JSON into the Options struct
	err := yaml.Unmarshal(raw, &opt)
	return opt, err
}
