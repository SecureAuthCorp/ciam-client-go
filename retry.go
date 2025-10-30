package acpclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/cloudentity/acp-client-go/clients/system/models"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"golang.org/x/sync/singleflight"
)

const (
	ErrorInvalidAccessToken = "invalid_access_token"
)

type Authenticator struct {
	transport *http.Client

	client *http.Client
	config clientcredentials.Config

	renewers singleflight.Group
}

func NewAuthenticator(config clientcredentials.Config, client *http.Client) *http.Client {
	return &http.Client{
		Transport: &Authenticator{
			transport: config.Client(context.WithValue(context.Background(), oauth2.HTTPClient, client)),
			config:    config,
			client:    client,
		},
	}
}

func (t *Authenticator) RoundTrip(req *http.Request) (*http.Response, error) {
	var reqBuf bytes.Buffer

	// Clone body using TeeReader for potential retry
	if req.Body != nil {
		reqReader := io.TeeReader(req.Body, &reqBuf)
		defer req.Body.Close()
		req.Body = io.NopCloser(reqReader)
	}

	// First attempt
	res, err := t.transport.Do(req)

	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	// Check if we need token renewal
	if t.shouldGetNewTokenAndRetry(res) {
		t.renew(req.Context())

		req2 := req.Clone(req.Context())
		// Restore request body
		if req2.Body != nil {
			req2.Body = io.NopCloser(&reqBuf)
		}

		// init next request which will start by minting a new token
		return t.transport.Do(req2)
	}

	return res, nil
}

// init new client to clear token cache and enforce minting a new token
// use singleflight to avoid concurrent renewals
func (t *Authenticator) renew(ctx context.Context) {
		_, _, _ = t.renewers.Do("renew", func() (interface{}, error) {
			t.transport = t.config.Client(context.WithValue(ctx, oauth2.HTTPClient, t.client))

			return nil, nil
		})
}

func (t *Authenticator) shouldGetNewTokenAndRetry(res *http.Response) bool {
	if res.StatusCode == http.StatusUnauthorized && res.Body != nil {
		var (
			resBuf    bytes.Buffer
			resReader = io.TeeReader(res.Body, &resBuf)
			decoder   = json.NewDecoder(resReader)
			merr      = models.Error{}
			err       error
		)

		defer res.Body.Close()

		// Restore response body
		res.Body = io.NopCloser(&resBuf)

		if err = decoder.Decode(&merr); err != nil {
			// not propagating error as the payload may contain a logical error with a different format
			return false
		}

		return merr.ErrorCode == ErrorInvalidAccessToken
	}

	return false
}
