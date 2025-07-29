package groups

type groupTime struct {
	interval  string
	fieldName string
	maxValues int
}

var _ Group = &groupTime{}

func NewGroupTime(fieldName string, interval string, maxValues int) Group {
	return &groupTime{
		interval:  interval,
		fieldName: fieldName,
		maxValues: maxValues,
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
