package option

import (
	"fmt"
	"os"
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
