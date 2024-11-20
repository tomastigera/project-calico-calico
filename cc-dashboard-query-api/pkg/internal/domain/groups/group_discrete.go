package groups

type groupDiscrete struct {
	maxValues int
	fieldName string
	sortOrder GroupSortOrder
}

var _ Group = &groupDiscrete{}

const defaultMaxValue = 10

func NewGroupDiscrete(fieldName string, maxValues int, sortOrder GroupSortOrder) Group {
	if maxValues == 0 {
		maxValues = defaultMaxValue
	}

	return &groupDiscrete{
		maxValues: maxValues,
		fieldName: fieldName,
		sortOrder: sortOrder,
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

func (g *groupDiscrete) SortOrder() GroupSortOrder {
	return g.sortOrder
}
