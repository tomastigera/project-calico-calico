// Copyright (c) 2024 Tigera, Inc. All rights reserved.
package parser

// The code in `parser.go` was inspired by code and code snippets of the
// seclang module in the coraza https://github.com/corazawaf/coraza/tree/main
// repo. Although heavily modified for our own custom needs.

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
)

type Rule struct {
	Id             string       `json:"id"`
	SecRule        string       `json:"secRule"`
	Operator       string       `json:"operator"`
	Variables      string       `json:"variables"`
	Transformation string       `json:"transformations"`
	Raw            string       `json:"raw"`
	Message        string       `json:"msg"`
	Actions        []RuleAction `json:"actions"`
}

type RuleAction struct {
	Key   string
	Value string
}

// this function was inspired by `parseString` found in
// https://github.com/corazawaf/coraza/blob/main/internal/seclang/parser.go
func Parse(f string) ([]Rule, error) {

	scanner := bufio.NewScanner(strings.NewReader(f))
	inBackticks := false
	var linebuffer strings.Builder
	rules := []Rule{}
	currentRule := Rule{}
	rawLine := ""

	for scanner.Scan() {
		line := scanner.Text()
		lineLen := len(line)
		if lineLen == 0 {
			if currentRule.SecRule != "" && currentRule.Operator != "" {
				rules = append(rules, currentRule)
			}

			currentRule = Rule{}
			continue
		}

		if line[0] == '#' {
			continue
		}

		if !inBackticks && line[lineLen-1] == '`' {
			inBackticks = true
		} else if inBackticks && line[0] == '`' {
			inBackticks = false
		}

		if inBackticks {
			linebuffer.WriteString(line)
			linebuffer.WriteString("\n")
			continue
		}

		rawLine += line + "\n"
		// Check if line ends with \ it is still one rule
		if line[lineLen-1] == '\\' {
			linebuffer.WriteString(strings.TrimSuffix(line, "\\"))
		} else {
			// handle chaining rules and rules that are one line next to each other
			linebuffer.WriteString(line)
			completeLine := linebuffer.String()
			leading_spaces := len(completeLine) - len(strings.TrimLeft(completeLine, " "))
			if leading_spaces == 0 {

				if currentRule.SecRule != "" && currentRule.Operator != "" {
					rules = append(rules, currentRule)
				}

				currentRule = Rule{}
			}

			rawLine = strings.TrimSuffix(rawLine, "\n")

			err := EvalLine(strings.TrimLeft(linebuffer.String(), " "), rawLine, &currentRule)
			if err != nil {
				return []Rule{}, err
			}
			rawLine = ""

			linebuffer.Reset()
		}
	}

	// add the last rule
	if currentRule.SecRule != "" || currentRule.Operator != "" {
		rules = append(rules, currentRule)
	}

	return rules, nil
}

func EvalLine(l, rawRule string, rule *Rule) error {
	line := strings.TrimSpace(l)
	if line == "" {
		return fmt.Errorf("error trimming space from : %v", l)
	}

	if line[0] == '#' {
		return fmt.Errorf("error starts with a comment : %v", line)
	}
	// first we get the directive
	secrule, opts, _ := strings.Cut(line, " ")

	variables, opts, _ := strings.Cut(opts, " ")

	operators, transformations, _ := strings.Cut(opts, "\" ")
	operators += "\""

	// if it's a chain rule
	if rule.Transformation != "" {
		newString := []string{
			secrule,
			variables,
			operators,
			transformations,
		}
		rule.Transformation += strings.Join(newString, "")
		rule.Raw += rawRule
		return nil
	}

	var err error

	rule.SecRule = secrule
	rule.Operator = operators
	rule.Transformation = transformations
	rule.Variables = variables
	rule.Raw = rawRule

	rule.Actions, err = parseTransformers(transformations)
	if err != nil {
		logrus.Error(err)
	}

	for _, act := range rule.Actions {
		if act.Key == "id" {
			rule.Id = act.Value
		}
		if act.Key == "msg" {
			rule.Message = strings.Trim(act.Value, "'")
		}
	}

	return nil
}

// parseTransformers will assign the function name, arguments and
// function (pkg.actions) for each action split by comma (,)
// Action arguments are allowed to wrap values between colons(”)
// this function was inspired by parseActions found in
// https://github.com/corazawaf/coraza/blob/main/internal/seclang/rule_parser.go
func parseTransformers(actions string) ([]RuleAction, error) {
	res := []RuleAction{}
	var err error

	beforeKey := -1 // index before first char of key
	afterKey := -1  // index after last char of key and before first char of value

	inQuotes := false
	for i := 1; i < len(actions); i++ {
		c := actions[i]
		if actions[i-1] == '\\' {
			// Escaped character, no need to process
			continue
		}
		if c == '\'' {
			inQuotes = !inQuotes
			continue
		}
		if inQuotes {
			// Inside quotes, no need to process
			continue
		}
		switch c {
		case ':':
			if afterKey != -1 {
				// Reading value, no need to process
				continue
			}
			afterKey = i
		case ',':
			var val string
			if afterKey == -1 {
				// No value, we only have a key
				afterKey = i
			} else {
				val = actions[afterKey+1 : i]
			}
			res, err = appendRuleAction(res, actions[beforeKey+1:afterKey], val)
			if err != nil {
				return nil, err
			}
			beforeKey = i
			afterKey = -1
		}
	}
	var val string
	if afterKey == -1 {
		// No value, we only have a key
		afterKey = len(actions)
	} else {
		val = actions[afterKey+1:]
	}
	res, err = appendRuleAction(res, actions[beforeKey+1:afterKey], val)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func appendRuleAction(res []RuleAction, key string, val string) ([]RuleAction, error) {
	key = strings.ToLower(strings.TrimSpace(key))
	key = strings.Trim(key, "\"")
	val = strings.TrimSpace(val)
	val = strings.Trim(val, "\"")
	val = strings.Trim(val, "'")

	res = append(res, RuleAction{
		Key:   key,
		Value: val,
	})

	return res, nil
}
