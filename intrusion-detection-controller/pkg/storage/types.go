// Copyright 2019 Tigera Inc. All rights reserved.

package storage

import (
	"encoding/json"
	"time"
)

type Duration struct {
	time.Duration
}

func (f *Duration) UnmarshalJSON(data []byte) error {
	var i int64
	if err := json.Unmarshal(data, &i); err == nil {
		f.Duration = time.Second * time.Duration(i)
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	f.Duration = d
	return nil
}

func (f Duration) MarshalJSON() ([]byte, error) {
	s := time.Duration(f.Duration).String()
	return json.Marshal(&s)
}

type Time struct {
	time.Time
}

func (t *Time) UnmarshalJSON(data []byte) error {
	var i int64
	if err := json.Unmarshal(data, &i); err == nil {
		t.Time = time.Time(time.Unix(i/1000, (time.Duration(i%1000) * time.Millisecond).Nanoseconds()))
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return err
	}
	t.Time = tm
	return nil
}

func (t Time) MarshalJSON() ([]byte, error) {
	s := time.Time(t.Time).Format(time.RFC3339)
	return json.Marshal(&s)
}
