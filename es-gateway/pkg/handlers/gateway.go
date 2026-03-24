// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package handlers

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"os"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	calicotls "github.com/projectcalico/calico/crypto/pkg/tls"
	"github.com/projectcalico/calico/es-gateway/pkg/middlewares"
	"github.com/projectcalico/calico/es-gateway/pkg/proxy"
	"github.com/projectcalico/calico/lma/pkg/logutils"
)

type loggerRoundTripper struct {
	defaultTransport http.RoundTripper
}

func (t *loggerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	b, err := httputil.DumpRequestOut(req, false)
	if err != nil {
		return nil, err
	}
	logrus.Trace(string(b))

	return t.defaultTransport.RoundTrip(req)
}

// GetProxyHandler generates an HTTP proxy handler based on the given Target.
func GetProxyHandler(t *proxy.Target, modifyResponseFunc func(*http.Response) error) (http.HandlerFunc, error) {
	p := &httputil.ReverseProxy{
		FlushInterval: -1,
		// Use Rewrite to configure the outbound request. SetURL rewrites the
		// target URL (equivalent to what the old default Director did) and
		// SetXForwarded sets X-Forwarded-For/Proto/Host headers.
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(t.Dest)
			pr.SetXForwarded()
			// Set the request Host explicitly so it matches the destination.
			pr.Out.Host = t.Dest.Host
		},
	}

	if t.Transport != nil {
		p.Transport = &loggerRoundTripper{defaultTransport: t.Transport}
	} else if t.Dest.Scheme == "https" {
		tlsCfg, err := calicotls.NewTLSConfig()
		if err != nil {
			return nil, err
		}

		if t.AllowInsecureTLS {
			tlsCfg.InsecureSkipVerify = true
		} else {
			if len(t.CAPem) == 0 {
				return nil, fmt.Errorf("failed to create target handler for path %s: ca bundle was empty", t.Dest)
			}

			logrus.Debugf("Detected secure transport for %s. Will pick up system cert pool", t.Dest)
			var ca *x509.CertPool
			ca, err := x509.SystemCertPool()
			if err != nil {
				logrus.WithError(err).Warn("failed to get system cert pool, creating a new one")
				ca = x509.NewCertPool()
			}

			file, err := os.ReadFile(t.CAPem)
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("could not read cert from file %s", t.CAPem))
			}

			ca.AppendCertsFromPEM(file)
			tlsCfg.RootCAs = ca

			if t.EnableMutualTLS {
				clientCert, err := tls.LoadX509KeyPair(t.ClientCert, t.ClientKey)
				if err != nil {
					return nil, err
				}
				tlsCfg.Certificates = []tls.Certificate{clientCert}
			}
		}

		p.Transport = &loggerRoundTripper{defaultTransport: &http.Transport{
			TLSClientConfig: tlsCfg,
		}}

		// Use the modify response hook function to logrus the return value for response.
		// This is useful for troubleshooting and debugging.
		p.ModifyResponse = modifyResponseFunc
	}
	p.ErrorLog = log.New(logutils.NewLogrusWriter(logrus.WithFields(logrus.Fields{"proxy": "outbound"})), "", log.LstdFlags)
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value(middlewares.ESUserKey)
		// User could be nil if this is a path that does not require authentication.
		if user != nil {
			user, ok := r.Context().Value(middlewares.ESUserKey).(*middlewares.User)
			// This should never happen (logical bug somewhere else in the code). But we'll
			// leave this check here to help catch it.
			if !ok {
				logrus.Error("unable to authenticate user: ES user cannot be pulled from context (this is a logical bug)")
				http.Error(w, "unable to authenticate user", http.StatusUnauthorized)
				return
			}
			logrus.Debugf("Received request %s from %s (authenticated for user %s), will proxy to %s", r.RequestURI, r.RemoteAddr, user.Username, t.Dest)
		} else {
			logrus.Debugf("Received request %s from %s, will proxy to %s", r.RequestURI, r.RemoteAddr, t.Dest)
		}

		p.ServeHTTP(w, r)
	}, nil
}
