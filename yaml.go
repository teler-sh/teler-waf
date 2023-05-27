package teler

import (
	"fmt"
	"io"
	"os"

	"github.com/go-playground/validator/v10"
	"github.com/kitabisa/teler-waf/request"
	"gopkg.in/yaml.v3"
)

type yamlCondition struct {
	Method  string `yaml:"method,omitempty"`
	Element string `yaml:"element,omitempty"`
	Pattern string `yaml:"pattern" validate:"required"`
}

type yamlRule struct {
	Name      string           `yaml:"name" validate:"required"`
	Condition string           `yaml:"condition,omitempty"`
	Rules     []*yamlCondition `yaml:"rules" validate:"required,dive"`
}

func validateYAMLRules(fl validator.FieldLevel) bool {
	// Retrieve the YAML string from the field
	yamlString, ok := fl.Field().Interface().(string)
	if !ok {
		return false
	}

	// Unmarshal the YAML string into a yamlRule struct
	var data yamlRule
	err := yaml.Unmarshal([]byte(yamlString), &data)
	if err != nil {
		return false
	}

	// Create a new validator instance
	validate := validator.New()

	// Validate the yamlRule struct
	err = validate.Struct(data)
	if err != nil {
		return false
	}

	return true
}

func yamlToRule(file *os.File) (Rule, error) {
	defer file.Close()

	// Create a new validator instance
	validate := validator.New()

	// Register the custom validation function
	validate.RegisterValidation("yaml", validateYAMLRules)

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
			if c.Method == "" {
				c.Method = defaultMethod
			}

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
