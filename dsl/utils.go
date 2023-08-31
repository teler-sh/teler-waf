// Copyright Dwi Siswanto and/or licensed to Dwi Siswanto under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.
// See the LICENSE-ELASTIC file in the project root for more information.

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
