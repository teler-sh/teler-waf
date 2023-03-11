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
