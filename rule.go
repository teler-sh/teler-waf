package teler

// Rule is custom security rules to apply to incoming requests.
type Rule struct {
	// Name is the name of the rule.
	Name string

	// Condition specifies the logical operator to use when evaluating the
	// rule's conditions. Valid values are "and" and "or".
	Condition string

	// Rules is a list of conditions that must be satisfied for the rule to
	// be triggered. Each condition specifies a request element to match and
	// a pattern to match against the element.
	Rules []Condition
}
