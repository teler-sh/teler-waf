package teler

import "regexp"

type cwa struct {
	Filters []struct {
		Description string      `json:"description"`
		ID          string      `json:"id"`
		Impact      string      `json:"impact"`
		Rule        string      `json:"rule"`
		Tags        interface{} `json:"tags"`
		pattern     *regexp.Regexp
	} `json:"filters"`
}
