package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/lma/pkg/auth"
	esauth "github.com/projectcalico/calico/ui-apis/pkg/auth"
)

// The handler returned by this will add a ResourceAttribute to the context
// of the request based on the content of the kibana query index-pattern
// (query.bool.filter.match.index-pattern.title)
func KibanaIndexPattern(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {

		name, err := getResourceNameFromKibanaIndexPattern(req)
		if err != nil {
			log.WithError(err).Debugf("Unable to extract kibana index pattern as resource")
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		h.ServeHTTP(w, req.WithContext(auth.NewContextWithReviewResource(req.Context(), esauth.CreateLMAResourceAttributes("cluster", name))))
	})
}

// getResourceNameFromKibanaIndexPattern parses the query.bool.filter.match.index-pattern.title
// from a kibana query request body and returns the RBAC resource
func getResourceNameFromKibanaIndexPattern(req *http.Request) (string, error) {

	// Read the body data
	b, err := io.ReadAll(req.Body)
	if err != nil {
		log.WithError(err).Debug("Error reading request body")
		return "", err
	}

	//  reset the request body
	req.Body = io.NopCloser(bytes.NewBuffer(b))

	// unmarshal the json
	var k kibanaReq
	err = json.Unmarshal(b, &k)
	if err != nil {
		log.WithError(err).WithField("body", string(b[:])).Debug("JSON parse error")
		return "", err
	}

	// extract the index pattern title
	title := k.Query.Bool.Filter[0].Match.IndexPatternTitle

	re := regexp.MustCompile(`([_a-z*]*)`)

	titleMatch := re.FindStringSubmatch(title)
	if len(titleMatch) != 2 {
		return "", fmt.Errorf("invalid index pattern in title, '%s' had %d matches", title, len(titleMatch))
	}

	resource, ok := queryToResource(titleMatch[0])
	if !ok {
		return "", fmt.Errorf("invalid resource '%s' in kibana index-pattern", title)
	}
	log.WithField("title", title).WithField("resource", resource).Info("kibana index-pattern")
	return resource, nil
}

// kibanaReq and kibanaReqMatch are for parsing a json doc formatted like this:
// {
//     "query": {
//         "bool": {
//             "filter": [
//                 {
//                     "match": {
//                         "index-pattern.title": "tigera_secure_ee_flows"
//                     }
//                 }
//             ]
//         }
//     }
// }

type kibanaReq struct {
	Query struct {
		Bool struct {
			Filter []kibanaReqMatch `json:"filter"`
		} `json:"bool"`
	} `json:"query"`
}

type kibanaReqMatch struct {
	Match struct {
		IndexPatternTitle string `json:"index-pattern.title"`
	} `json:"match"`
}
