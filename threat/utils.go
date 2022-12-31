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

// Filepath returns the file path representation of a Threat value
func (t Threat) Filepath() (string, error) {
	files := map[Threat]string{
		CommonWebAttack:     "common-web-attacks.json",
		CVE:                 "cves.json",
		BadIPAddress:        "bad-ip-addresses.txt",
		BadReferrer:         "bad-referrers.txt",
		BadCrawler:          "bad-crawlers.txt",
		DirectoryBruteforce: "directory-bruteforces.txt",
	}

	path, err := location()
	if err != nil {
		return "", err
	}

	if file, ok := files[t]; ok {
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
