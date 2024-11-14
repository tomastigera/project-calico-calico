package groups

type groupTime struct {
	interval  string
	fieldName string
}

var _ Group = &groupTime{}

func NewGroupTime(fieldName string, interval string) Group {
	return &groupTime{
		interval:  interval,
		fieldName: fieldName,
	}
}

func (g *groupTime) FieldName() string {
	return g.fieldName
}

func (g *groupTime) MaxValues() int {
	return 0
}

func (g *groupTime) Interval() string {
	return g.interval
}

func (g *groupTime) Type() GroupType {
	return GroupTypeTime
}
