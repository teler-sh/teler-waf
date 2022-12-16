package teler

import (
    "regexp"

    "github.com/kitabisa/teler-waf/request"
)

// Condition specifies a request element to match and
// a pattern to match against the element.
type Condition struct {
    // Element is the request element to match.
    // These element are defined in the request.Element type.
    Element request.Element

    // Pattern is the regular expression to match against the element.
    Pattern string

    // patternRegex saves the compiled regular expressions of the
    // Pattern for subsequent use.
    patternRegex *regexp.Regexp
}
