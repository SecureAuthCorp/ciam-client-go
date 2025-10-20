package acpclient

import (
	"context"
	"net/http"
	"sync"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
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

func (t *Authenticator) RoundTrip(req *http.Request) (res *http.Response, err error) {
	if res, err = t.transport.Do(req); err != nil {
		return res, err
	} else if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
		t.renew(req.Context())
		return t.transport.Do(req)
	}

	return res, nil
}

func (t *Authenticator) renew(ctx context.Context) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.transport = t.config.Client(context.WithValue(ctx, oauth2.HTTPClient, t.client))
}
