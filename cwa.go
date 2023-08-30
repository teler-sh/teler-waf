// Copyright Dwi Siswanto and/or licensed to Dwi Siswanto under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.
// See the LICENSE-ELv2 file in the project root for more information.

package teler

type cwa struct {
	Filters []struct {
		Description string   `json:"description"`
		ID          int64    `json:"id"`
		Impact      int64    `json:"impact"`
		Rule        string   `json:"rule"`
		Tags        []string `json:"tags"`
		pattern     interface{}
	} `json:"filters"`
}
