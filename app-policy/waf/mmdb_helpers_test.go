package waf_test

import (
	"bytes"
	"net"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

// createSingleRUEntryMMDB creates a minimal MMDB with a single entry for 95.173.136.1 (RU)
func createSingleRUEntryMMDB() ([]byte, error) {
	importMMDBWriter()
	writer, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType: "GeoIP2-Country",
		RecordSize:   24,
	})
	if err != nil {
		return nil, err
	}

	_, ipnet, err := net.ParseCIDR("95.173.136.1/32")
	if err != nil {
		return nil, err
	}
	record := mmdbtype.Map{
		"country": mmdbtype.Map{
			"iso_code": mmdbtype.String("RU"),
		},
	}

	if err := writer.Insert(ipnet, record); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if _, err := writer.WriteTo(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// importMMDBWriter is a dummy function to ensure mmdbwriter imports are present
func importMMDBWriter() {
	_ = mmdbwriter.Options{}
	_ = mmdbtype.Map{}
}
