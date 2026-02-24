package server

import (
	clientv3 "github.com/tigera/api/pkg/client/clientset_generated/clientset/typed/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	capi "github.com/projectcalico/calico/compliance/pkg/api"
)

const (
	QueryFormat = "format"
	QueryReport = ":report"
	UrlList     = "/compliance/reports"
	UrlGet      = "/compliance/reports/:report"
	UrlDownload = "/compliance/reports/:report/download"
	UrlVersion  = "/compliance/version"

	UrlParamReportTypeName = "reportTypeName"
	UrlParamReportName     = "reportName"
	UrlParamPage           = "page"
	UrlParamFromTime       = "fromTime"
	UrlParamToTime         = "toTime"
	UrlParamMaxItems       = "maxItems"
	UrlParamSortBy         = "sortBy"
	AllResults             = "all"
	DefaultMaxItems        = 100
	SortAscendingSuffix    = "/ascending"
	SortDescendingSuffix   = "/descending"
)

var (
	ValidSortBy = []string{
		"reportName", "reportTypeName", "generationTime", "startTime", "endTime",
	}

	DefaultSortBy = []capi.ReportSortBy{
		{Field: "startTime", Ascending: false}, {Field: "reportTypeName", Ascending: true}, {Field: "reportName", Ascending: true},
	}
)

// ServerControl is the interface used to control the state of the compliance server.
type ServerControl interface {
	Start()
	Stop()
	Wait()
}

// ReportConfigurationGetter is the interface required by the server for querying the report and report types.
type ReportConfigurationGetter interface {
	clientv3.GlobalReportsGetter
	clientv3.GlobalReportTypesGetter
}

// ReportList is a list of reports. This is serialized as json when returned over http.
type ReportList struct {
	Reports []Report `json:"reports"`
	Page    int      `json:"page"`
	Count   int      `json:"count"`
}

// Report is a single rendered report (summary). This is serialized as json when returned over http.
type Report struct {
	Id              string      `json:"id"`
	Name            string      `json:"name"`
	Type            string      `json:"type"`
	StartTime       metav1.Time `json:"startTime"`
	EndTime         metav1.Time `json:"endTime"`
	UISummary       any         `json:"uiSummary"`
	DownloadURL     string      `json:"downloadUrl"`
	DownloadFormats []Format    `json:"downloadFormats"`
	GenerationTime  metav1.Time `json:"generationTime"`
}

// A format that the report may be downloaded as.
type Format struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// The version of the compliance-server. This is serialized as json and returned on the version uri.
type VersionData struct {
	Version   string `json:"version"`
	BuildDate string `json:"buildDate"`
	GitTagRef string `json:"gitTagRef"`
	GitCommit string `json:"gitCommit"`
}
