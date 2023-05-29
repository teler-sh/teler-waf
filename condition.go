package teler

import (
	"regexp"

	"github.com/antonmedv/expr/vm"
	"github.com/kitabisa/teler-waf/request"
)

// Condition specifies a request element to match and
// a pattern or DSL expression to match against the element.
type Condition struct {
	// Method is the HTTP method to match against.
	// It is of type request.Method, which is a type alias for string.
	//
	// It will be ignored if DSL is not empty.
	Method request.Method

	// Element is the request element to match.
	// These element are defined in the request.Element type.
	//
	// It will be ignored if DSL is not empty.
	Element request.Element

	// Pattern is the regular expression to match against the element.
	//
	// It will be ignored if DSL is not empty.
	Pattern string

	// patternRegex saves the compiled regular expressions of the
	// Pattern for subsequent use.
	patternRegex *regexp.Regexp

	// DSL is the DSL expression to match against the incoming requests.
	DSL string

	// dslProgram saves the compiled DSL expressions of the code
	// for subsequent use.
	dslProgram *vm.Program
}
