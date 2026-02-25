// Copyright (c) 2019 Tigera Inc. All rights reserved.

package puller

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/yalp/jsonpath"
)

type entryHandler func(n int, s string)

type parser func(r io.Reader, h entryHandler) error

func getParserForFormat(f v3.ThreatFeedFormat) parser {
	switch {
	case f.JSON != nil:
		return jsonParser(f.JSON.Path)
	case f.CSV != nil:
		return csvParser(f.CSV)
	default:
		return newlineDelimitedParser
	}
}

func jsonParser(path string) parser {
	filter, filterErr := jsonpath.Prepare(path)

	return func(r io.Reader, h entryHandler) error {
		if filterErr != nil {
			return filterErr
		}

		input, err := io.ReadAll(r)
		if err != nil {
			return fmt.Errorf("could not read data: %s", err)
		}

		var i any
		err = json.Unmarshal(input, &i)
		if err != nil {
			return fmt.Errorf("could not parse JSON: %s", err)
		}

		i2, err := filter(i)
		if err != nil {
			return fmt.Errorf("could not read jsonpath: %s", err)
		}

		lines, ok := i2.([]any)
		if !ok {
			log.WithField("output", i2).Warn("[Global Threat Feeds] path does not produce an array of strings")
			return fmt.Errorf("[Global Threat Feeds] path does not produce an array of strings")
		}

		var once sync.Once
		for idx, e := range lines {
			s, ok := e.(string)
			if ok {
				h(idx+1, s)
			} else {
				once.Do(func() {
					log.WithFields(log.Fields{
						"object_num": idx,
						"object":     e,
					}).Warn("[Global Threat Feeds] expected string")
				})
			}
		}

		return nil
	}
}

func csvParser(f *v3.ThreatFeedFormatCSV) parser {
	return func(r io.Reader, h entryHandler) error {
		c := csv.NewReader(r)

		if len(f.ColumnDelimiter) > 0 {
			c.Comma = []rune(f.ColumnDelimiter)[0]
		}
		if len(f.CommentDelimiter) > 0 {
			c.Comment = []rune(f.CommentDelimiter)[0]
		}

		c.FieldsPerRecord = f.RecordSize
		if f.DisableRecordSizeValidation {
			c.FieldsPerRecord = -1
		}

		var fieldNum int
		if f.FieldNum != nil {
			fieldNum = int(*f.FieldNum)
		}
		if f.Header {
			header, err := c.Read()
			if err != nil {
				return err
			}
			if f.FieldName != "" {
				var found bool
				for idx, h := range header {
					if h == f.FieldName {
						fieldNum = idx
						found = true
						break
					}
				}
				if !found {
					return fmt.Errorf("[Global Threat Feeds] header %s not found", f.FieldName)
				}
			}
		}

		n := 0
		for {
			n++
			r, err := c.Read()
			if err != nil {
				if err == io.EOF {
					break
				}
				return err
			}

			if len(r) > fieldNum {
				h(n, r[fieldNum])
			}
		}

		return nil
	}
}

func newlineDelimitedParser(r io.Reader, h entryHandler) error {
	// Response format is one item per line.
	s := bufio.NewScanner(r)
	var n = 0
	for s.Scan() {
		n++
		l := s.Text()
		// filter comments
		i := strings.Index(l, CommentPrefix)
		if i >= 0 {
			l = l[0:i]
		}
		// strip whitespace
		l = strings.TrimSpace(l)
		// filter blank lines
		if len(l) == 0 {
			continue
		}
		h(n, l)
	}
	return s.Err()
}
