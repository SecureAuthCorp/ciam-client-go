package acpclient_test

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"testing"

	acpclient "github.com/cloudentity/acp-client-go"
	"github.com/cloudentity/acp-client-go/mocks"
	"golang.org/x/oauth2/clientcredentials"
)

var ccConfig = clientcredentials.Config{
	TokenURL: "http://example.com/oauth2/token",
}

func TestAuthenticatorRoundTrip(t *testing.T) {
	tests := []struct {
		name           string
		mock           http.RoundTripper
		requestBody    string
		expectedStatus int
		expectedError  bool
		wantNilResp    bool
	}{
		{
			name:           "successful request without retry",
			mock:           &mocks.MockAuthTransport{},
			requestBody:    "",
			expectedStatus: http.StatusOK,
			expectedError:  false,
		},
		{
			name:           "successful request with body without retry",
			mock:           &mocks.MockAuthTransport{},
			requestBody:    "test body",
			expectedStatus: http.StatusOK,
			expectedError:  false,
		},
		{
			name:           "unauthorized with invalid token triggers retry and succeeds",
			mock:           &mocks.MockAuthTransport{},
			requestBody:    "test body for retry",
			expectedStatus: http.StatusOK,
			expectedError:  false,
		},
		{
			name:           "token renewal failure",
			mock:           &mocks.MockAuthTransport{FailRenewal: true},
			requestBody:    "test body",
			expectedStatus: 0,
			expectedError:  true,
			wantNilResp:    true,
		},
		{
			name:           "transport error",
			mock:           &mocks.MockTransport{Response: nil, Error: errors.New("transport failure")},
			requestBody:    "",
			expectedStatus: 0,
			expectedError:  true,
			wantNilResp:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &http.Client{Transport: tt.mock}
			authClient := acpclient.NewAuthenticator(ccConfig, client)

			var reqBody io.ReadCloser
			if tt.requestBody != "" {
				reqBody = io.NopCloser(bytes.NewBufferString(tt.requestBody))
			}

			req, err := http.NewRequest("GET", "http://example.com/api/test", reqBody)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			res, err := authClient.Transport.RoundTrip(req)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				if tt.wantNilResp && res != nil {
					t.Errorf("Expected nil response, got %+v", res)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if res == nil {
					t.Error("Expected response, got nil")
				} else if res.StatusCode != tt.expectedStatus {
					t.Errorf("Expected status %d, got %d", tt.expectedStatus, res.StatusCode)
				}
			}
		})
	}
}