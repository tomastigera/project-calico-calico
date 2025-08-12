// Copyright (c) 2021 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package query defines a domain-specific query language to select which records from the data set
// should be used in the GlobalAlert. The query language is translated to the Elastic DSL queries
// that are executed on the backend.
//
// Query strings are parsed by alecthomas/participle language parser into a Left node (single Term) and
// a Right node (an array of OpTerm).
//
//   - A Term will be recursively parsed into a Left node (single UnaryOpTerm) and a Right node (an array of OpValue).
//   - An OpTerm will be recursively parsed into a Left node (single UnaryOpTerm) and a Right node (an array of OpValue).
//   - An OpValue contains one or more UnaryOpTerm.
//   - A UnaryOpTerm contains a Negator operator and a Value, which can be one of Atom, Set, OpTerm, or Subquery.
//   - A SubQuery will be recursively parsed again like an upper level Query or SubQuery.
//
// Here is an example of an annotated query string.
//
//	       a = b              AND NOT c > d     OR e < f              AND               (  g IN {h, i, j}     OR k != l  )
//	       |                  |   |   |         |  |                  |                 |  |                  |  |
//	       |                  |   |   |         |  |                  |                 |  |                  |  Atom
//	       |                  |   |   |         |  |                  |                 |  |                  |  |
//	       |                  |   |   |         |  |                  |                 |  |                  |  UnaryOpTerm
//	       |                  |   |   |         |  |                  |                 |  |                  |
//	       |                  |   |   |         |  |                  |                 |  Set                |
//	       |                  |   |   |         |  |                  |                 |  |                  |
//	       |                  |   |   |         |  |                  |                 |  Left: UnaryOpTerm  |
//	       |                  |   |   |         |  |                  |                 |  |                  |
//	       |                  |   |   |         |  |                  |                 |  Left: Term         Right: []OpTerm
//	       |                  |   |   |         |  |                  |                 |
//	Query: |                  |   |   |         |  |                  |                 Subquery
//	       |                  |   |   |         |  |                  |                 |
//	       |                  |   |   |         |  |                  |                 UnaryOpTerm
//	       |                  |   |   |         |  |                  |
//	       |                  |   |   |         |  Atom               |
//	       |                  |   |   |         |  |                  |
//	       |                  |   |   |         |  Left: UnaryOpTerm  Right: []OpValue
//	       |                  |   |   |         |
//	       |                  |   |   Atom      |
//	       |                  |   |             |
//	       |                  |   UnaryOpTerm   |
//	       |                  |                 |
//	       Atom               |                 |
//	       |                  |                 |
//	       Left: UnaryOpTerm  Right: []OpValue  |
//	       |                                    |
//	Query: Left: Term                           Right: []OpTerm
package query
