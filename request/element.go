// Licensed to Dwi Siswanto under one or more agreements.
// Dwi Siswanto licenses this file to you under the Apache 2.0 License.
// See the LICENSE-APACHE file in the project root for more information.

package request

/*
Element represents the different elements of a request that can be matched.

The Element type is used to specify which element of a request should be matched
when analyzing the request for threats. It can be one of the following values:

  - URI: specifies the request URI (path and query parameters) as the element to match
  - Headers: specifies the request headers as the element to match
  - Body: specifies the request body as the element to match
*/
type Element int

const (
	// URI specifies the request URI (path and query parameters) as the request element to match.
	URI Element = iota

	// Headers specifies the request headers as the request element to match.
	Headers

	// Body specifies the request body as the request element to match.
	Body

	// Any specifies that any element of the request should be matched.
	Any
)
