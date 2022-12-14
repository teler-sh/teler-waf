package teler

import "github.com/kitabisa/teler-waf/request"

type Condition struct {
    // Element is the request element to match.
    // These element are defined in the request.Element type.
    Element int

    // Pattern is the regular expression to match against the element.
    Pattern string
}
