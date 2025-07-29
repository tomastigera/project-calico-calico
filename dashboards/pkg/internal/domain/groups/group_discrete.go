package groups

type groupDiscrete struct {
	maxValues int
	fieldName string
}

var _ Group = &groupDiscrete{}

const defaultMaxValue = 10

func NewGroupDiscrete(fieldName string, maxValues int) Group {
	if maxValues == 0 {
		maxValues = defaultMaxValue
	}

	return &groupDiscrete{
		maxValues: maxValues,
		fieldName: fieldName,
	}
}

func (g *groupDiscrete) FieldName() string {
	return g.fieldName
}

func (g *groupDiscrete) MaxValues() int {
	return g.maxValues
}

func (g *groupDiscrete) Interval() string {
	return ""
}

func (g *groupDiscrete) Type() GroupType {
	return GroupTypeDiscrete
}
