// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package query

import (
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = DescribeTable("Validate", func(
	input string,
	isValid Validator,
	ok bool) {
	query, err := ParseQuery(input)
	Expect(err).ShouldNot(HaveOccurred())

	err = Validate(query, isValid)
	if !ok {
		Expect(err).Should(HaveOccurred())
	} else {
		Expect(err).ShouldNot(HaveOccurred())
	}
},

	Entry("empty query", "", func(*Atom) error { return nil }, true),
	Entry("null validator", "a = b", func(*Atom) error { return nil }, true),
	Entry("always fails", "a = b", func(*Atom) error { return errors.New("error") }, false),
	Entry("bad key", "a = b AND c = d", func(a *Atom) error {
		if a.Key == "c" {
			return errors.New("error")
		}
		return nil
	}, false),
	Entry("two valid keys", "a = b AND b = c", func(a *Atom) error {
		switch a.Key {
		case "a", "b":
			return nil
		default:
			return errors.New("error")
		}
	}, true),
)
