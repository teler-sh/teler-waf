package threat

type Exclude int

const (
	// CommonWebAttack threat type covers common web-based attacks such as cross-site scripting (XSS) and SQL injection.
	CommonWebAttack Exclude = iota

	// CVE threat type covers known vulnerabilities and exploits, as specified by the Common Vulnerabilities and Exposures (CVE) database.
	CVE

	// BadIPAddress threat type covers requests from known bad IP addresses, such as those associated with known malicious actors or botnets.
	BadIPAddress

	// BadReferrer threat type covers requests with a bad HTTP referrer, such as those that are not expected based on the application's URL structure or are known to be associated with malicious actors.
	BadReferrer

	// BadCrawler threat type covers requests from known bad crawlers or scrapers, such as those that are known to cause performance issues or attempt to extract sensitive information from the application.
	BadCrawler

	// DirectoryBruteforce threat type covers requests that attempt to brute-force access to directories on the server, such as by trying common directory names or using dictionary attacks.
	DirectoryBruteforce
)
