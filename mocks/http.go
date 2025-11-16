package mocks

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	acpclient "github.com/cloudentity/acp-client-go"
	"github.com/cloudentity/acp-client-go/clients/system/models"
)

// MockTransport implements http.RoundTripper for testing
// It returns a custom response and error for each call
type MockTransport struct {
	Response *http.Response
	Error    error
}

func (m *MockTransport) Do(req *http.Request) (*http.Response, error) {
	return m.Response, m.Error
}

func (m *MockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.Do(req)
}

type MockAuthTransport struct {
	// If true, the token endpoint will return an OAuth2 error instead of a token.
	FailRenewal bool
}

func (s *MockAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return s.respond(req), nil
}

func (s *MockAuthTransport) respond(req *http.Request) *http.Response {
	jsonResp := func(status int, body string) *http.Response {
		h := make(http.Header)
		h.Set("Content-Type", "application/json")
		return &http.Response{
			Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
			StatusCode: status,
			Header:     h,
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    req,
		}
	}

	path := req.URL.Path

	switch {
	case strings.HasPrefix(path, "/api"): // adjust to your resource path(s)
		token := strings.TrimSpace(req.Header.Get("Authorization"))
		hasValid := token == "Bearer valid"
		if !hasValid {
			merr := models.Error{ErrorCode: acpclient.ErrorInvalidAccessToken}
			b, _ := json.Marshal(merr)
			return jsonResp(http.StatusUnauthorized, string(b))
		}
		return jsonResp(http.StatusOK, `{"ok":true}`)

	case strings.Contains(path, "/oauth2/token"):
		if s.FailRenewal {
			return jsonResp(http.StatusUnauthorized, `{"error":"invalid_client","error_description":"Invalid client credentials"}`)
		}
		return jsonResp(http.StatusOK, `{"access_token":"valid","token_type":"bearer","expires_in":3600}`)

	default:
		panic(fmt.Sprintf("unexpected request path in MockAuthTransport: %s", path))
	}
}
