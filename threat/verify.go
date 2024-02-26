// Licensed to Dwi Siswanto under one or more agreements.
// Dwi Siswanto licenses this file to you under the Apache 2.0 License.
// See the LICENSE-APACHE file in the project root for more information.

package threat

import (
	"bufio"
	"fmt"
	"strings"

	"net/http"
	"path/filepath"

	"github.com/codingsince1985/checksum"
)

// Verify checks the integrity of files by comparing their checksums with the
// MD5 sums obtained from a teler-resources repository.
//
// It fetches the MD5 sums, verifies that the fetched data is correct, and then
// checks the checksums of the local files against the obtained MD5 sums. It
// returns true if all checksums match, otherwise returns false along with an
// error if any issues occur during the verification process.
func Verify() (bool, error) {
	md5sums, err := fetchMD5Sums()
	if err != nil {
		return false, err
	}

	return verifyChecksums(md5sums)
}

// fetchMD5Sums retrieves MD5 sums from a remote source and returns them as a
// map where filenames are the keys and MD5 sums are the values.
//
// In case of an error during the retrieval, it returns an error.
func fetchMD5Sums() (map[string]string, error) {
	// Initialize a map to store the MD5 sums
	md5sums := make(map[string]string)

	resp, err := http.Get(sumURL)
	if err != nil {
		return md5sums, fmt.Errorf(errGetSumFile, err)
	}
	defer resp.Body.Close()

	// Create a scanner to read the file content line by line
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()

		// Split each line into filename and MD5 sum
		parts := strings.Fields(line)
		if len(parts) == 2 {
			filename, md5 := parts[1], parts[0]
			if filename == dbFile {
				continue
			}

			md5sums[filename] = md5
		}
	}

	// Check for errors during scanning
	if err := scanner.Err(); err != nil {
		return md5sums, fmt.Errorf(errReadSumFile, err)
	}

	return md5sums, nil
}

// verifyChecksums compares the MD5 sums obtained from a remote source
// with the local checksums of the files. It takes a map of filenames to
// MD5 sums as input and returns true if all checksums match, otherwise
// returns false along with an error if any checksums do not match.
func verifyChecksums(md5sums map[string]string) (bool, error) {
	for _, threat := range List() {
		p, err := threat.Filename(true)
		if err != nil {
			return false, err
		}

		sum, err := checksum.MD5sum(p)
		if err != nil {
			return false, fmt.Errorf(errChecksum, p, err)
		}

		f := filepath.Base(p)
		if md5sum := md5sums[f]; sum != md5sum {
			return false, fmt.Errorf(errMalformed, threat.String(), md5sum, sum)
		}
	}

	return true, nil
}
