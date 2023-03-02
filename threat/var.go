package threat

import "fmt"

var (
	DbURL   = fmt.Sprintf("%s/raw/master/db/db.tar.zst", repoURL)
	dbQuery = fmt.Sprintf("checksum=file:%s/raw/master/db/MD5SUMS", repoURL)
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
