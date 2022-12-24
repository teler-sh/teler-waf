package teler

type cve struct {
	Templates []struct {
		ID   string `json:"id"`
		Info struct {
			Name     string `json:"name"`
			Severity string `json:"severity"`
		} `json:"info"`
		Requests []interface{} `json:"requests"`
	} `json:"templates"`
}
