package teler

type cve struct {
	Templates []struct {
		Id   string `json:"id"`
		Info struct {
			Name     string `json:"name"`
			Severity string `json:"severity"`
		} `json:"info"`
		Requests []interface{} `json:"requests"`
	} `json:"templates"`
}
