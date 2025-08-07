package filters

type CriterionType string

type Criterion interface {
	Negate() bool
}

type Criteria []Criterion
