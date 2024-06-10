// Copyright Dwi Siswanto and/or licensed to Dwi Siswanto under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.
// See the LICENSE-ELASTIC file in the project root for more information.

package teler

import (
	"fmt"
	"io"
	"os"

	"github.com/go-playground/validator/v10"
	"github.com/teler-sh/teler-waf/request"
	"gopkg.in/yaml.v3"
)

type yamlCondition struct {
	Method  string `yaml:"method,omitempty"`
	Element string `yaml:"element,omitempty"`
	Pattern string `yaml:"pattern,omitempty"`
	DSL     string `yaml:"dsl,omitempty"`
}

type yamlRule struct {
	Name      string           `yaml:"name" validate:"required"`
	Condition string           `yaml:"condition,omitempty"`
	Rules     []*yamlCondition `yaml:"rules" validate:"required,dive"`
}

func yamlToRule(file *os.File) (Rule, error) {
	defer file.Close()

	// Create a new validator instance
	validate := validator.New()

	// Initialize Rule and slice of yamlRule pointer
	var rule Rule
	var yamlRules []*yamlRule

	// Read the contents of the YAML file
	yamlData, err := io.ReadAll(file)
	if err != nil {
		return rule, fmt.Errorf(errReadFile, err.Error())
	}

	// Unmarshal the YAML data into a slice of yamlRule structs
	err = yaml.Unmarshal(yamlData, &yamlRules)
	if err != nil {
		return rule, fmt.Errorf(errUnmarshalYAML, err.Error())
	}

	// Iterate over each yamlRule and convert it to a Rule
	for _, r := range yamlRules {
		rule.Name = r.Name

		// Set default values if they are not specified in the YAML rule
		if r.Condition == "" {
			r.Condition = defaultCondition
		}
		rule.Condition = r.Condition

		// Initialize teler custom rule condition
		rule.Rules = make([]Condition, len(r.Rules))

		// Convert each sub-rule to the Rule struct
		for i, c := range r.Rules {
			// If DSL expression is not empty, then skip
			if c.DSL != "" {
				rule.Rules[i].DSL = c.DSL
				continue
			}

			// Check if DSL expression or regular expression pattern is empty
			if c.DSL == "" && c.Pattern == "" {
				return rule, fmt.Errorf(errInvalidYAML, "DSL or pattern cannot be empty")
			}

			// If method is empty, set to default value
			if c.Method == "" {
				c.Method = defaultMethod
			}

			// If element is empty, set to default value
			if c.Element == "" {
				c.Element = defaultElement
			}

			// convert a method string to corresponding request.Method value
			rule.Rules[i].Method = request.ToMethod(c.Method)
			if rule.Rules[i].Method == request.UNDEFINED {
				return rule, fmt.Errorf(errConvValRule, c.Method, "method", r.Name)
			}

			// convert a element string to corresponding request.Element value
			rule.Rules[i].Element = request.ToElement(c.Element)
			if rule.Rules[i].Element == -1 {
				return rule, fmt.Errorf(errConvValRule, c.Element, "element", r.Name)
			}

			rule.Rules[i].Pattern = c.Pattern
		}

		// Validate the yamlRule struct
		err = validate.Struct(r)
		if err != nil {
			return rule, fmt.Errorf(errInvalidYAML, err.Error())
		}
	}

	return rule, nil
}
