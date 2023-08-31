// Copyright Dwi Siswanto and/or licensed to Dwi Siswanto under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.
// See the LICENSE-ELASTIC file in the project root for more information.

package option

import (
	"os"
	"testing"

	"github.com/kitabisa/teler-waf"
	"github.com/stretchr/testify/assert"
)

var (
	jsonConfig = []byte(`{
  "excludes": [
    4,
    5
  ],
  "whitelists": [
    "request.Headers matches \"(curl|Go-http-client|okhttp)/*\" && threat == BadCrawler",
    "request.URI startsWith \"/wp-login.php\"",
    "request.IP in [\"127.0.0.1\", \"::1\", \"0.0.0.0\"]",
    "request.Headers contains \"authorization\" && request.Method == \"POST\""
  ],
  "customs": [
    {
      "name": "Log4j Attack",
      "condition": "or",
      "rules": [
        {
          "method": "GET",
          "element": 0,
          "pattern": "\\$\\{.*:\\/\\/.*\\/?\\w+?\\}",
          "dsl": ""
        }
      ]
    },
    {
      "name": "Body Contains \"foo\" String",
      "condition": "or",
      "rules": [
        {
          "method": "",
          "element": 0,
          "pattern": "",
          "dsl": "request.Body contains \"foo\""
        }
      ]
    },
    {
      "name": "Headers Contains \"curl\" String",
      "condition": "or",
      "rules": [
        {
          "method": "",
          "element": 0,
          "pattern": "",
          "dsl": "request.Headers contains \"curl\""
        }
      ]
    },
    {
      "name": "Request IP Address is Localhost",
      "condition": "or",
      "rules": [
        {
          "method": "",
          "element": 0,
          "pattern": "",
          "dsl": "request.IP in [\"127.0.0.1\", \"::1\", \"0.0.0.0\"]"
        }
      ]
    },
    {
      "name": "LDAP Injection",
      "condition": "or",
      "rules": [
        {
          "method": "ALL",
          "element": 3,
          "pattern": "(and|or|not|&&|\\|\\|)",
          "dsl": ""
        }
      ]
    },
    {
      "name": "Method is GET",
      "condition": "or",
      "rules": [
        {
          "method": "",
          "element": 0,
          "pattern": "",
          "dsl": "request.Method == \"GET\""
        }
      ]
    },
    {
      "name": "Request Contains \"foo\" String",
      "condition": "or",
      "rules": [
        {
          "method": "",
          "element": 0,
          "pattern": "",
          "dsl": "one(request.ALL, # contains \"foo\")"
        }
      ]
    },
    {
      "name": "SQL Injection",
      "condition": "or",
      "rules": [
        {
          "method": "ALL",
          "element": 0,
          "pattern": "(union|select|insert|update|delete|drop|alter)",
          "dsl": ""
        }
      ]
    }
  ],
  "customs_from_file": "",
  "response": {
    "status": 403,
    "html": "Your request has been denied for security reasons. Ref: {{ID}}.",
    "html_file": ""
  },
  "log_file": "/tmp/teler.log",
  "no_stderr": false,
  "no_update_check": false,
  "development": false,
  "in_memory": false,
  "falcosidekick_url": ""
}`)

	yamlConfig = []byte(`excludes:
    - 4
    - 5
whitelists:
    - request.Headers matches "(curl|Go-http-client|okhttp)/*" && threat == BadCrawler
    - request.URI startsWith "/wp-login.php"
    - request.IP in ["127.0.0.1", "::1", "0.0.0.0"]
    - request.Headers contains "authorization" && request.Method == "POST"
customs:
    - name: Log4j Attack
      condition: or
      rules:
        - method: GET
          element: 0
          pattern: \$\{.*:\/\/.*\/?\w+?\}
          dsl: ""
    - name: Body Contains "foo" String
      condition: or
      rules:
        - method: ""
          element: 0
          pattern: ""
          dsl: request.Body contains "foo"
    - name: Headers Contains "curl" String
      condition: or
      rules:
        - method: ""
          element: 0
          pattern: ""
          dsl: request.Headers contains "curl"
    - name: Request IP Address is Localhost
      condition: or
      rules:
        - method: ""
          element: 0
          pattern: ""
          dsl: request.IP in ["127.0.0.1", "::1", "0.0.0.0"]
    - name: LDAP Injection
      condition: or
      rules:
        - method: ALL
          element: 3
          pattern: (and|or|not|&&|\|\|)
          dsl: ""
    - name: Method is GET
      condition: or
      rules:
        - method: ""
          element: 0
          pattern: ""
          dsl: request.Method == "GET"
    - name: Request Contains "foo" String
      condition: or
      rules:
        - method: ""
          element: 0
          pattern: ""
          dsl: 'one(request.ALL, # contains "foo")'
    - name: SQL Injection
      condition: or
      rules:
        - method: ALL
          element: 0
          pattern: (union|select|insert|update|delete|drop|alter)
          dsl: ""
customs_from_file: ""
response:
  status: 403
  html: "Your request has been denied for security reasons. Ref: {{ID}}."
  html_file: ""
log_file: /tmp/teler.log
no_stderr: false
no_update_check: false
development: false
in_memory: false
falcosidekick_url: ""`)
)

func TestLoadFromJSONBytes(t *testing.T) {
	opt, err := LoadFromJSONBytes(jsonConfig)
	if err != nil {
		t.Errorf("Failed to load JSON bytes: %v", err)
	}

	assert.NotEqual(t, opt, teler.Options{})
}

func TestLoadFromJSONString(t *testing.T) {
	opt, err := LoadFromJSONString(string(jsonConfig))
	if err != nil {
		t.Errorf("Failed to load JSON string: %v", err)
	}

	assert.NotEqual(t, opt, teler.Options{})
}

func TestLoadFromJSONFile(t *testing.T) {
	// Create a temporary JSON file
	tmpfile, err := os.CreateTemp("", "config*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name()) // Clean up the temporary file

	// Write JSON data to the temporary file
	err = os.WriteFile(tmpfile.Name(), jsonConfig, 0644)
	if err != nil {
		t.Fatal(err)
	}

	opt, err := LoadFromJSONFile(tmpfile.Name())
	if err != nil {
		t.Errorf("Failed to load JSON file: %v", err)
	}

	assert.NotEqual(t, opt, teler.Options{})
}

func TestLoadFromYAMLBytes(t *testing.T) {
	opt, err := LoadFromYAMLBytes(yamlConfig)
	if err != nil {
		t.Errorf("Failed to load YAML bytes: %v", err)
	}

	assert.NotEqual(t, opt, teler.Options{})
}

func TestLoadFromYAMLString(t *testing.T) {
	opt, err := LoadFromYAMLString(string(yamlConfig))
	if err != nil {
		t.Errorf("Failed to load YAML string: %v", err)
	}

	assert.NotEqual(t, opt, teler.Options{})
}

func TestLoadFromYAMLFile(t *testing.T) {
	// Create a temporary YAML file
	tmpfile, err := os.CreateTemp("", "config*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name()) // Clean up the temporary file

	// Write YAML data to the temporary file
	err = os.WriteFile(tmpfile.Name(), yamlConfig, 0644)
	if err != nil {
		t.Fatal(err)
	}

	opt, err := LoadFromYAMLFile(tmpfile.Name())
	if err != nil {
		t.Errorf("Failed to load YAML file: %v", err)
	}

	assert.NotEqual(t, opt, teler.Options{})
}
