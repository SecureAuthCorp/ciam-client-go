package acpclient_test

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"reflect"
	"testing"

	acpclient "github.com/cloudentity/acp-client-go"
	"github.com/cloudentity/acp-client-go/mocks"
	"golang.org/x/oauth2/clientcredentials"
)

var ccConfig = clientcredentials.Config{
		TokenURL: "http://example.com/oauth2/token",
	}

func TestAuthenticatorRoundTrip_TokenRenewalFails(t *testing.T) {
	seqTransport := &mocks.MockAuthTransport{FailRenewal: true}
	client := &http.Client{Transport: seqTransport}
	authClient := acpclient.NewAuthenticator(ccConfig, client)

	req, _ := http.NewRequest("GET", "http://example.com/api/test", io.NopCloser(bytes.NewBufferString("test")))
	res, err := authClient.Transport.RoundTrip(req)
	if err == nil {
		t.Fatal("Expected error when token renewal fails, got nil")
	}
	if res != nil {
		t.Errorf("Expected nil response when token renewal fails, got %+v", res)
	}
}

func TestNewAuthenticator(t *testing.T) {
	client := &http.Client{}
	newClient := acpclient.NewAuthenticator(ccConfig, client)
	if newClient == nil {
		t.Fatal("NewAuthenticator returned nil client")
	}
	if reflect.TypeOf(newClient.Transport).String() != "*acpclient.Authenticator" {
		t.Errorf("Transport type mismatch: got %T", newClient.Transport)
	}
}

func TestAuthenticatorRoundTrip_Success(t *testing.T) {
	mock := &mocks.MockAuthTransport{}
	client := &http.Client{Transport: mock}
	authClient := acpclient.NewAuthenticator(ccConfig, client)

	req, _ := http.NewRequest("GET", "http://example.com/api/test", nil)
	res, err := authClient.Transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Errorf("Expected status OK, got %d", res.StatusCode)
	}
}

func TestAuthenticatorRoundTrip_UnauthorizedWithInvalidToken(t *testing.T) {
	seqTransport := &mocks.MockAuthTransport{}
	client := &http.Client{Transport: seqTransport}
	authClient := acpclient.NewAuthenticator(ccConfig, client)

	req, _ := http.NewRequest("GET", "http://example.com/api/test", io.NopCloser(bytes.NewBufferString("test")))
	res, err := authClient.Transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Errorf("Expected status OK after retry and renewal, got %d", res.StatusCode)
	}
}

func TestAuthenticatorRoundTrip_Error(t *testing.T) {
	mock := &mocks.MockTransport{Response: nil, Error: errors.New("fail")}
	client := &http.Client{Transport: mock}
	authClient := acpclient.NewAuthenticator(ccConfig, client)

	req, _ := http.NewRequest("GET", "http://example.com/api/test", nil)
	_, err := authClient.Transport.RoundTrip(req)
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
}

func TestAuthenticatorRenew(t *testing.T) {
	client := &http.Client{}
	authClient := acpclient.NewAuthenticator(ccConfig, client)
	if authClient.Transport == nil {
		t.Error("Expected transport to be set after NewAuthenticator")
	}
}
