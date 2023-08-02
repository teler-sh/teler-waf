package dsl

// GetRequestValue from the Requests environment
func (e *Env) GetRequestValue(k string) string {
	e.mu.Lock()
	defer e.mu.Unlock()

	if v, ok := e.Requests[k]; ok {
		return v.(string)
	}

	return ""
}
