// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package fv_test

import (
	"bytes"
	"io"
	"net/http"
)

func doRequest(method, url string, headers map[string]string, body []byte) (*http.Response, []byte, error) {
	var err error
	req, err := http.NewRequest(method, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	client := http.DefaultClient
	res, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		err = res.Body.Close()
	}()

	if err != nil {
		return nil, nil, err
	}
	var resBody []byte
	resBody, err = io.ReadAll(res.Body)
	if err != nil {
		return nil, nil, err
	}

	return res, resBody, nil
}
