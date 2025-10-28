package acpclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/cloudentity/acp-client-go/clients/system/models"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

const (
	ErrorInvalidAccessToken = "invalid_access_token"
)

type Authenticator struct {
	transport *http.Client

	client *http.Client
	config clientcredentials.Config

	mutex sync.Mutex
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

	// Restore request body
	if req.Body != nil {
		req.Body = io.NopCloser(&reqBuf)
	}

	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	// Check if we need token renewal
	if res.StatusCode == http.StatusUnauthorized && res.Body != nil {
		var (
			resBuf    bytes.Buffer
			resReader = io.TeeReader(res.Body, &resBuf)
			decoder   = json.NewDecoder(resReader)
			merr      = models.Error{}
		)

		defer res.Body.Close()

		if err = decoder.Decode(&merr); err != nil {
			return nil, fmt.Errorf("failed to parse error response: %w", err)
		}

		// Restore response body
		res.Body = io.NopCloser(&resBuf)

		if merr.ErrorCode == ErrorInvalidAccessToken {
			t.renew(req.Context())

			return t.transport.Do(req)
		}
	}

	return res, nil
}

func (t *Authenticator) renew(ctx context.Context) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.transport = t.config.Client(context.WithValue(ctx, oauth2.HTTPClient, t.client))
}
