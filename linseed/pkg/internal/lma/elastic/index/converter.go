// Copyright 2021 Tigera Inc. All rights reserved.

package index

import (
	"github.com/projectcalico/calico/libcalico-go/lib/validator/v3/query"
)

type JsonObject map[string]any

type JsonObjectElasticQuery JsonObject

func (q JsonObjectElasticQuery) Source() (any, error) {
	return JsonObject(q), nil
}

type queryObject interface {
	*query.Atom | *query.SetOpTerm
}

type converterFunc[E queryObject] func(queryObject E) JsonObject

// Converter contains a single field that defines a function that will implement the query atom to
// elastic JsonObject. If the instance does not implement its own version of function, then the
// instance can define the basicAtomToElastic as the atomToElastic.
type converter struct {
	atomToElastic               func(atom *query.Atom) JsonObject
	setOpTermToElastic          func(s *query.SetOpTerm) JsonObject
	unaryPostfixOpTermToElastic func(v *query.UnaryPostfixOpTerm) JsonObject
}

// comparatorToElastic converts the comparator to an elastic JsonObject.
func comparatorToElastic(c query.Comparator, key string, value any) JsonObject {
	switch c {
	case query.CmpEqual:
		return JsonObject{
			"term": JsonObject{
				key: JsonObject{
					"value": value,
				},
			},
		}
	case query.CmpNotEqual:
		return JsonObject{
			"bool": JsonObject{
				"must_not": JsonObject{
					"term": JsonObject{
						key: JsonObject{
							"value": value,
						},
					},
				},
			},
		}
	case query.CmpLt, query.CmpLte, query.CmpGt, query.CmpGte:
		return JsonObject{
			"range": JsonObject{
				key: JsonObject{
					c.ToElasticFunc(): value,
				},
			},
		}
	}
	panic("unknown operator")
}

// basicAtomToElastic implements the basic atomToElastic Converter function.
func basicAtomToElastic(k *query.Atom) JsonObject {
	return comparatorToElastic(k.Comparator, k.Key, k.Value)
}

// Converter.

// Converter constructs and returns an elastic JsonObject representing a query.
func (c converter) Convert(q *query.Query) JsonObject {
	if q.Left == nil {
		return JsonObject{
			"match_all": JsonObject{},
		}
	}
	terms := []JsonObject{c.termToElastic(q.Left)}

	for _, r := range q.Right {
		terms = append(terms, c.opTermToElastic(r))
	}

	if len(terms) == 1 {
		return terms[0]
	}

	return JsonObject{
		"bool": JsonObject{
			"should": terms,
		},
	}
}

func (c converter) valueToElastic(v *query.Value) JsonObject {
	if v.Atom != nil {
		return c.atomToElastic(v.Atom)
	}
	if v.Set != nil {
		return c.setOpTermToElastic(v.Set)
	}
	if v.Subquery != nil {
		return c.Convert(v.Subquery)
	}
	if v.OpTerm != nil && c.unaryPostfixOpTermToElastic != nil {
		return c.unaryPostfixOpTermToElastic(v.OpTerm)
	}
	panic("empty value")
}

func (c converter) unaryOpTermToElastic(v *query.UnaryOpTerm) JsonObject {
	if v.Negator != nil {
		return JsonObject{
			"bool": JsonObject{
				"must_not": c.valueToElastic(v.Value),
			},
		}
	}
	return c.valueToElastic(v.Value)
}

func basicSetOpTermToElastic(s *query.SetOpTerm) JsonObject {
	terms := []JsonObject{}
	for _, k := range s.Members {
		terms = append(terms, JsonObject{
			"wildcard": JsonObject{
				s.Key: JsonObject{
					"value": k.Value,
				},
			},
		})
	}

	if s.Operator == query.OpNotIn {
		return JsonObject{
			"bool": JsonObject{
				"must_not": terms,
			},
		}
	}

	return JsonObject{
		"bool": JsonObject{
			"should": terms,
		},
	}
}

func (c converter) opValueToElastic(o *query.OpValue) JsonObject {
	return c.unaryOpTermToElastic(o.Value)
}

func (c converter) termToElastic(t *query.Term) JsonObject {
	terms := []JsonObject{c.unaryOpTermToElastic(t.Left)}
	for _, r := range t.Right {
		terms = append(terms, c.opValueToElastic(r))
	}

	if len(terms) == 1 {
		return terms[0]
	}

	return JsonObject{
		"bool": JsonObject{
			"must": terms,
		},
	}
}

func (c converter) opTermToElastic(o *query.OpTerm) JsonObject {
	return c.termToElastic(o.Term)
}
