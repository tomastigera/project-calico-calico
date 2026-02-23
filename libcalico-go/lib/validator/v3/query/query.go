// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.

package query

import (
	"fmt"
	"go/token"
	"strings"

	"github.com/alecthomas/participle"
)

type JsonObject map[string]any

var (
	parser = participle.MustBuild(&Query{})
)

type Operator int

const (
	OpAnd Operator = iota
	OpOr
	OpNot
	OpIn
	OpNotIn
	OpEmpty
)

var operatorMap = map[string]Operator{
	"AND":   OpAnd,
	"and":   OpAnd,
	"&&":    OpAnd,
	"OR":    OpOr,
	"or":    OpOr,
	"||":    OpOr,
	"NOT":   OpNot,
	"not":   OpNot,
	"!":     OpNot,
	"IN":    OpIn,
	"in":    OpIn,
	"NOTIN": OpNotIn,
	"notin": OpNotIn,
	"EMPTY": OpEmpty,
	"empty": OpEmpty,
}

func (o *Operator) Capture(s []string) error {
	v, ok := operatorMap[s[0]]
	if !ok {
		return fmt.Errorf("unknown operator: %s", s[0])
	}
	*o = v
	return nil
}

type Comparator int

const (
	CmpEqual Comparator = iota
	CmpNotEqual
	CmpLt
	CmpLte
	CmpGt
	CmpGte
)

var comparatorMap = map[string]Comparator{
	"=":  CmpEqual,
	"!=": CmpNotEqual,
	"<":  CmpLt,
	"<=": CmpLte,
	">":  CmpGt,
	">=": CmpGte,
}

func (c *Comparator) Capture(s []string) error {
	v, ok := comparatorMap[strings.Join(s, "")]
	if !ok {
		return fmt.Errorf("unknown operator: %s", s[0])
	}
	*c = v
	return nil
}

func (c Comparator) ToElasticFunc() string {
	switch c {
	case CmpLt:
		return "lt"
	case CmpLte:
		return "lte"
	case CmpGt:
		return "gt"
	case CmpGte:
		return "gte"
	}
	panic("unknown operator")
}

type Atom struct {
	Key        string     `parser:"@(Ident | String)"`
	Comparator Comparator `parser:"@(\"=\" | \"!\" \"=\" | \"<\" \"=\" | \"<\" | \">\" \"=\" | \">\")"`
	Value      string     `parser:"@(Ident | String | Int | Float)"`
}

type Value struct {
	Atom     *Atom               `parser:"@@"`
	Set      *SetOpTerm          `parser:"| @@"`
	OpTerm   *UnaryPostfixOpTerm `parser:"| @@"`
	Subquery *Query              `parser:"| \"(\" @@ \")\""`
}

type Member struct {
	Value string `parser:"@(Ident | String)"`
}

type UnaryOpTerm struct {
	Negator *Operator `parser:"@(\"NOT\" | \"not\" | \"!\")?"`
	Value   *Value    `parser:"@@"`
}

type UnaryPostfixOpTerm struct {
	Key      string   `parser:"@(Ident | String)"`
	Operator Operator `parser:"@(\"EMPTY\" | \"empty\")"`
}

type SetOpTerm struct {
	Key      string    `parser:"@(Ident | String)"`
	Operator Operator  `parser:"@(\"IN\" | \"in\" | \"NOTIN\" | \"notin\")"`
	Members  []*Member `parser:"\"{\" @@ ( \",\" @@ )* \"}\""`
}

type OpValue struct {
	Operator Operator     `parser:"@(\"AND\" | \"and\" | \"&&\")"`
	Value    *UnaryOpTerm `parser:"@@"`
}

type Term struct {
	Left  *UnaryOpTerm `parser:"@@"`
	Right []*OpValue   `parser:"@@*"`
}

type OpTerm struct {
	Operator Operator `parser:"@(\"OR\" | \"or\" | \"||\")"`
	Term     *Term    `parser:"@@"`
}

type Query struct {
	Left  *Term     `parser:"@@?"`
	Right []*OpTerm `parser:"@@*"`
}

// String

func (o Operator) String() string {
	switch o {
	case OpAnd:
		return "AND"
	case OpOr:
		return "OR"
	case OpNot:
		return "NOT"
	case OpIn:
		return "IN"
	case OpNotIn:
		return "NOTIN"
	case OpEmpty:
		return "EMPTY"
	}
	panic(fmt.Sprintf("unknown operator: %d", o))
}

func (c Comparator) String() string {
	switch c {
	case CmpEqual:
		return "="
	case CmpNotEqual:
		return "!="
	case CmpLt:
		return "<"
	case CmpLte:
		return "<="
	case CmpGt:
		return ">"
	case CmpGte:
		return ">="
	}
	panic(fmt.Sprintf("unknown comparator: %d", c))
}

func quoteIfNeeded(s string) string {
	if !(token.IsKeyword(s) || token.IsIdentifier(s)) {
		return fmt.Sprintf("%q", s)
	}
	return s
}

func (k Atom) String() string {
	return fmt.Sprintf("%s %s %s", quoteIfNeeded(k.Key), k.Comparator, quoteIfNeeded(k.Value))
}

func (v Value) String() string {
	if v.Atom != nil {
		return v.Atom.String()
	}
	if v.Set != nil {
		return v.Set.String()
	}
	if v.Subquery != nil {
		return "(" + v.Subquery.String() + ")"
	}
	if v.OpTerm != nil {
		return v.OpTerm.String()
	}
	panic("empty value")
}

func (k Member) String() string {
	return k.Value
}

func (v UnaryOpTerm) String() string {
	if v.Negator != nil {
		return "NOT " + v.Value.String()
	}
	return v.Value.String()
}

func (v UnaryPostfixOpTerm) String() string {
	return fmt.Sprintf("%s EMPTY", quoteIfNeeded(v.Key))
}

func (t SetOpTerm) String() string {
	out := []string{}
	for _, k := range t.Members {
		out = append(out, k.Value)
	}
	return fmt.Sprintf("%s %s {%s}", t.Key, t.Operator, strings.Join(out, ", "))
}

func (o OpValue) String() string {
	return fmt.Sprintf("%s %s", o.Operator, o.Value)
}

func (t Term) String() string {
	out := []string{t.Left.String()}
	for _, r := range t.Right {
		out = append(out, r.String())
	}
	return strings.Join(out, " ")
}

func (o OpTerm) String() string {
	return fmt.Sprintf("%s %s", o.Operator, o.Term)
}

func (q Query) String() string {
	if q.Left == nil {
		return ""
	}
	out := []string{q.Left.String()}
	for _, r := range q.Right {
		out = append(out, r.String())
	}
	return strings.Join(out, " ")
}

func ParseQuery(s string) (*Query, error) {
	query := &Query{}
	err := parser.ParseString(s, query)

	return query, err
}
