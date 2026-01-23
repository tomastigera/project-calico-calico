package client

type DashboardID string
type DashboardCardID string
type DashboardLayout map[string]any
type DashboardFilter map[string]any
type DashboardCardChart map[string]any
type DashboardCardQuery map[string]any
type DashboardCardMapping map[string]any

type PackageName string

type Dashboard struct {
	ID             DashboardID       `json:"id"`
	Title          string            `json:"title"`
	Cards          []DashboardCard   `json:"cards"`
	Layout         []DashboardLayout `json:"layout"`
	IsImmutable    bool              `json:"isImmutable,omitempty"`
	DefaultFilters []DashboardFilter `json:"defaultFilters"`
}

type DashboardSummary struct {
	ID          DashboardID `json:"id"`
	Title       string      `json:"title"`
	IsImmutable bool        `json:"isImmutable,omitempty"`
}

type DashboardCard struct {
	ID      DashboardCardID      `json:"id"`
	Title   string               `json:"title"`
	Chart   DashboardCardChart   `json:"chart"`
	Query   DashboardCardQuery   `json:"query"`
	Mapping DashboardCardMapping `json:"responseMapping"`
}

type DashboardListResponse struct {
	Dashboards []DashboardSummary `json:"dashboards"`
}

type DashboardCreateRequest struct {
	Title          string            `json:"title"`
	Cards          []DashboardCard   `json:"cards"`
	Layout         []DashboardLayout `json:"layout"`
	DefaultFilters []DashboardFilter `json:"defaultFilters"`
}

type DashboardUpdateRequest struct {
	Title          string            `json:"title"`
	Cards          []DashboardCard   `json:"cards"`
	Layout         []DashboardLayout `json:"layout"`
	DefaultFilters []DashboardFilter `json:"defaultFilters"`
}
