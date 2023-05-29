package dsl

import (
	"strings"

	"github.com/kitabisa/teler-waf/threat"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// Env represents the environment for the DSL.
type Env struct {
	// Threat represents a threat category.
	Threat threat.Threat

	// Requests is a map that holds incoming request information.
	Requests map[string]any

	// funcs is a map that associates function names with their respective functions.
	funcs map[string]any
}

// Env represents the environment for the DSL.
func New() *Env {
	// Create a new Env instance.
	env := &Env{}

	// Initialize Threat to Undefined
	env.Threat = threat.Undefined

	// Initialize funcs to a map of function names and their corresponding functions.
	env.funcs = map[string]any{
		"clone":       strings.Clone,
		"containsAny": strings.ContainsAny,
		"equalFold":   strings.EqualFold,
		"hasPrefix":   strings.HasPrefix,
		"hasSuffix":   strings.HasSuffix,
		"join":        strings.Join,
		"repeat":      strings.Repeat,
		"replace":     strings.Replace,
		"replaceAll":  strings.ReplaceAll,
		"request":     env.Requests,
		"threat":      env.Threat,
		"title":       cases.Title(language.Und).String,
		"toLower":     strings.ToLower,
		"toTitle":     strings.ToTitle,
		"toUpper":     strings.ToUpper,
		"toValidUTF8": strings.ToValidUTF8,
		"trim":        strings.Trim,
		"trimLeft":    strings.TrimLeft,
		"trimPrefix":  strings.TrimPrefix,
		"trimRight":   strings.TrimRight,
		"trimSpace":   strings.TrimSpace,
		"trimSuffix":  strings.TrimSuffix,
	}

	// Assign each threat category to the funcs map.
	for _, t := range threat.List() {
		env.funcs[t.String()] = t
	}

	// Return the initialized Env instance.
	return env
}
