package threat

// String returns the string representation of a Threat value
func (t Threat) String() string {
	if s, ok := str[t]; ok {
		return s
	}

	return ""
}

// List returns a slice of all Threat constants
func List() []Threat {
	var threats []Threat

	for t := range str {
		threats = append(threats, t)
	}

	return threats
}
