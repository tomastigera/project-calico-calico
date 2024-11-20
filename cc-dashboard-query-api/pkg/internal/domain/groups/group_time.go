package groups

type groupTime struct {
	interval  string
	fieldName string
	maxValues int
	sortOrder GroupSortOrder
}

var _ Group = &groupTime{}

func NewGroupTime(fieldName string, interval string, maxValues int, sortOrder GroupSortOrder) Group {
	return &groupTime{
		interval:  interval,
		fieldName: fieldName,
		maxValues: maxValues,
		sortOrder: sortOrder,
	}
}

func (g *groupTime) FieldName() string {
	return g.fieldName
}

func (g *groupTime) MaxValues() int {
	return g.maxValues
}

func (g *groupTime) Interval() string {
	return g.interval
}

func (g *groupTime) Type() GroupType {
	return GroupTypeTime
}

func (g *groupTime) SortOrder() GroupSortOrder {
	return g.sortOrder
}
