// Licensed to Dwi Siswanto under one or more agreements.
// Dwi Siswanto licenses this file to you under the Apache 2.0 License.
// See the LICENSE-APACHE file in the project root for more information.

package dsl

// GetRequestValue from the Requests environment
func (e *Env) GetRequestValue(k string) string {
	e.sl.Lock()
	defer e.sl.Unlock()

	if v, ok := e.Requests[k]; ok {
		return v.(string)
	}

	return ""
}
