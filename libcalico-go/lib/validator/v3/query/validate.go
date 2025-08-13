// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package query

func (v Value) Atoms() []*Atom {
	if v.Atom != nil {
		return []*Atom{v.Atom}
	}
	if v.Set != nil {
		// SetOpTerm doesn't contain Atoms but a set of ident|string.
		// The validation is enforced by the participle lexer grammar.
		return nil
	}
	if v.Subquery != nil {
		return v.Subquery.Atoms()
	}
	if v.OpTerm != nil {
		return nil
	}
	panic("empty value")
}

func (v UnaryOpTerm) Atoms() []*Atom {
	return v.Value.Atoms()
}

func (o OpValue) Atoms() []*Atom {
	return o.Value.Atoms()
}

func (t Term) Atoms() []*Atom {
	res := t.Left.Atoms()
	for _, r := range t.Right {
		res = append(res, r.Atoms()...)
	}
	return res
}

func (o OpTerm) Atoms() []*Atom {
	return o.Term.Atoms()
}

func (q Query) Atoms() []*Atom {
	if q.Left == nil {
		return nil
	}

	res := q.Left.Atoms()
	for _, r := range q.Right {
		res = append(res, r.Atoms()...)
	}

	return res
}

func Validate(e *Query, isValid Validator) error {
	for _, a := range e.Atoms() {
		if err := isValid(a); err != nil {
			return err
		}
	}

	return nil
}
