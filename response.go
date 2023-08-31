// Copyright Dwi Siswanto and/or licensed to Dwi Siswanto under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.
// See the LICENSE-ELASTIC file in the project root for more information.

package teler

// Response represents the configuration for custom error
// response pages when a request is blocked or rejected.
type Response struct {
	// Status defines the HTTP status code to be used in the response when a
	// request is blocked or rejected. Default is using DefaultStatusResponse.
	Status int `json:"status" yaml:"status"`

	// HTML defines the custom HTML response page that will be sent when
	// a request is blocked or rejected. This field allows you to specify the HTML
	// content directly as a string. It will be ignored if HTMLFile is set.
	// Beware that we DO NOT escape the HTML content.
	// Default is using DefaultHTMLResponse.
	HTML string `json:"html" yaml:"html"`

	// HTMLFile specifies the path to a file containing the custom HTML
	// response page. The contents of this file will be used as the custom response
	// page when a request is blocked or rejected. Beware that we DO NOT escape the
	// HTML content.
	HTMLFile string `json:"html_file" yaml:"html_file"`
}
