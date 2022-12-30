package threat

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
