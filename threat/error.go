// Licensed to Dwi Siswanto under one or more agreements.
// Dwi Siswanto licenses this file to you under the Apache 2.0 License.
// See the LICENSE-APACHE file in the project root for more information.

package threat

const (
	errFilepath    = "unable to get file path location of given %s threat type"
	errGetSumFile  = "unable to fetch checksum file: %w"
	errReadSumFile = "cannot read checksum file: %w"
	errChecksum    = "cannot perform checksum for '%s' file: %w"
	errMalformed   = "threat '%s' datasets is malformed, expect '%s' got '%s' sum"
)
