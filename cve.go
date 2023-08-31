// Copyright Dwi Siswanto and/or licensed to Dwi Siswanto under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.
// See the LICENSE-ELASTIC file in the project root for more information.

package teler

import "net/url"

// cveURL defines a slice of a pointer of the URLs for each CVE ID.
var cveURL map[string][]*url.URL

// TODO: how do we check HTTP method of CVE requests?
