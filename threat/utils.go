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

// List returns a slice of all Threat constants
func List() []Threat {
	var threats []Threat

	for t := range str {
		threats = append(threats, t)
	}

	return threats
}
