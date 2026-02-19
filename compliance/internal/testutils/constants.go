// Copyright (c) 2019 Tigera, Inc. SelectAll rights reserved.
package testutils

// We define a number of constants that are used to encapsulate name/namespace/label/selector and other useful
// information. Having these defined as numerical values will make it easy to script a scale test, just passing in
// incremental values for the name and namespace etc.

const (
	// Zero values with contextual meaning.
	NoLabels            = TestLabel(0)
	NoSelector          = Selector(0)
	NoNamespaceSelector = Selector(0)
	NoNamespace         = Namespace(0)
	NoPodOptions        = PodOpt(0)
	NoServiceAccount    = Name(0)

	// Other special values
	SelectAll = Selector(255)
)

// TestLabel value. This is a bit-mask and so may encapsulate multiple labels.
// Named TestLabel to avoid conflict with ginkgo v2's Label function.
type TestLabel byte

const (
	Label1 TestLabel = 1 << iota
	Label2
	Label3
	Label4
	Label5
)

// Selector value. This is a bit-mask and so may encapsulate multiple selectors.
type Selector byte

const (
	Select1 Selector = 1 << iota
	Select2
	Select3
	Select4
	Select5
)

// Name value. This is rendered as a string containing the value by the helper methods.
type Name int

const (
	NameDefault Name = 0 + iota
	Name1
	Name2
	Name3
	Name4
)

const (
	// Redefine names as tiers to make method calls clearer.
	TierDefault = NameDefault
	Tier1       = Name1
	Tier2       = Name2
)

// Name value. This is rendered as a string containing the value by the helper methods.
type Namespace int

const (
	Namespace1 Namespace = 1 + iota
	Namespace2
	Namespace3
	Namespace4
)

// Action value.
type Action byte

const (
	Allow Action = 1
	Deny  Action = 2
)

// Entity value referring to the source or destination in a Calico policy rule.
type Entity byte

const (
	Source Entity = 1 << iota
	Destination
)

// Net value which is rendered as a CIDR using the helper methods. Currently just support a Public and Private net.
type Net byte

const (
	Public Net = 1 << iota
	Private
)

// Label value. This is a bit-mask and so may encapsulate multiple labels. This is rendered as a single IP or a slice
// of IPs by the helper methods, depending on context.
type IP byte

const (
	IP1 IP = 1 << iota
	IP2
	IP3
	IP4
)

// Additional Pod options, indicating what features to configure in the pod.
type PodOpt byte

const (
	PodOptEnvoyEnabled PodOpt = 1 << iota
	PodOptSetGenerateName
)

// Additional policy options, indicating what features to configure in the pod.
type PolicyOpt byte

const (
	PolicyOptOrder1 PolicyOpt = 1 << iota
	PolicyOptOrder10
	PolicyOptOrder10000
	PolicyOptTier1
	PolicyOptTier2
)

var (
	Order1     float64 = 1.0
	Order10            = 10.0
	Order10000         = 10000.0
)
