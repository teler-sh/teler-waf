package teler

import "net/url"

// cveURL defines a slice of a pointer of the URLs for each CVE ID.
var cveURL map[string][]*url.URL

// TODO: how do we check HTTP method of CVE requests?
