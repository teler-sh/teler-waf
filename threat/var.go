// Licensed to Dwi Siswanto under one or more agreements.
// Dwi Siswanto licenses this file to you under the Apache 2.0 License.
// See the LICENSE-APACHE file in the project root for more information.

package threat

var (
	dbFile  = "db.tar.zst"
	DbURL   = repoURL + "/raw/master/db/" + dbFile
	sumURL  = repoURL + "/raw/master/db/MD5SUMS"
	dbQuery = "checksum=file:" + sumURL
)

var str = map[Threat]string{
	Undefined:           "Undefined",
	Custom:              "Custom",
	CommonWebAttack:     "CommonWebAttack",
	CVE:                 "CVE",
	BadIPAddress:        "BadIPAddress",
	BadReferrer:         "BadReferrer",
	BadCrawler:          "BadCrawler",
	DirectoryBruteforce: "DirectoryBruteforce",
}

var file = map[Threat]string{
	CommonWebAttack:     "common-web-attacks.json",
	CVE:                 "cves.json",
	BadIPAddress:        "bad-ip-addresses.txt",
	BadReferrer:         "bad-referrers.txt",
	BadCrawler:          "bad-crawlers.txt",
	DirectoryBruteforce: "directory-bruteforces.txt",
}
