package acpclient

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	obbrConsents "github.com/cloudentity/acp-client-go/clients/openbankingBR/consents/client"
	obbrPayments "github.com/cloudentity/acp-client-go/clients/openbankingBR/payments/client"

	obukAccounts "github.com/cloudentity/acp-client-go/clients/openbankingUK/accounts/client"
	obukPayments "github.com/cloudentity/acp-client-go/clients/openbankingUK/payments/client"

	o2Client "github.com/cloudentity/acp-client-go/clients/oauth2/client"
	o2Params "github.com/cloudentity/acp-client-go/clients/oauth2/client/oauth2"
	o2models "github.com/cloudentity/acp-client-go/clients/oauth2/models"

	adminClient "github.com/cloudentity/acp-client-go/clients/admin/client"
	developerClient "github.com/cloudentity/acp-client-go/clients/developer/client"

	identity "github.com/cloudentity/acp-client-go/clients/identity/client"
	identityroot "github.com/cloudentity/acp-client-go/clients/identityroot/client"
	identityself "github.com/cloudentity/acp-client-go/clients/identityself/client"
	identitysystem "github.com/cloudentity/acp-client-go/clients/identitysystem/client"

	licensingadmin "github.com/cloudentity/acp-client-go/clients/licensingadmin/client"
	licensingroot "github.com/cloudentity/acp-client-go/clients/licensingroot/client"

	publicClient "github.com/cloudentity/acp-client-go/clients/public/client"
	rootClient "github.com/cloudentity/acp-client-go/clients/root/client"
	systemClient "github.com/cloudentity/acp-client-go/clients/system/client"
	webClient "github.com/cloudentity/acp-client-go/clients/web/client"

	cdr "github.com/cloudentity/acp-client-go/clients/cdr/client"
	cdrcdr "github.com/cloudentity/acp-client-go/clients/cdr/client/c_d_r"
	cdrconsentpage "github.com/cloudentity/acp-client-go/clients/cdr/client/c_o_n_s_e_n_t_p_a_g_e"
	cdrdcr "github.com/cloudentity/acp-client-go/clients/cdr/client/d_c_r"
	cdrmanagement "github.com/cloudentity/acp-client-go/clients/cdr/client/m_a_n_a_g_e_m_e_n_t"

	fdx "github.com/cloudentity/acp-client-go/clients/fdx/client"
	fdxconsentpage "github.com/cloudentity/acp-client-go/clients/fdx/client/c_o_n_s_e_n_t_p_a_g_e"
	fdxdcr "github.com/cloudentity/acp-client-go/clients/fdx/client/d_c_r"
	fdxfdx "github.com/cloudentity/acp-client-go/clients/fdx/client/f_d_x"
	fdxmanagement "github.com/cloudentity/acp-client-go/clients/fdx/client/m_a_n_a_g_e_m_e_n_t"

	ksa "github.com/cloudentity/acp-client-go/clients/ksa/client"
	ksaconsentpage "github.com/cloudentity/acp-client-go/clients/ksa/client/c_o_n_s_e_n_t_p_a_g_e"

	obbr "github.com/cloudentity/acp-client-go/clients/obbr/client"
	obbrconsentpage "github.com/cloudentity/acp-client-go/clients/obbr/client/c_o_n_s_e_n_t_p_a_g_e"
	obbrdcr "github.com/cloudentity/acp-client-go/clients/obbr/client/d_c_r"
	obbrmanagement "github.com/cloudentity/acp-client-go/clients/obbr/client/m_a_n_a_g_e_m_e_n_t"
	obbrobbr "github.com/cloudentity/acp-client-go/clients/obbr/client/o_b_b_r"

	obuk "github.com/cloudentity/acp-client-go/clients/obuk/client"
	obukconsentpage "github.com/cloudentity/acp-client-go/clients/obuk/client/c_o_n_s_e_n_t_p_a_g_e"
	obukdcr "github.com/cloudentity/acp-client-go/clients/obuk/client/d_c_r"
	obukmanagement "github.com/cloudentity/acp-client-go/clients/obuk/client/m_a_n_a_g_e_m_e_n_t"
	obukobuk "github.com/cloudentity/acp-client-go/clients/obuk/client/o_b_u_k"

	opin "github.com/cloudentity/acp-client-go/clients/opin/client"
	opinopin "github.com/cloudentity/acp-client-go/clients/opin/client/o_p_i_n"

	hub "github.com/cloudentity/acp-client-go/clients/hub/client"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"

	"github.com/go-jose/go-jose/v4"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/pkg/errors"
	"golang.org/x/oauth2/clientcredentials"
)

const (
	NonceLength    = 20
	StateLength    = 8
	VerifierLength = 43
)

type Oauth2 struct {
	*o2Client.Acp
}

type Admin struct {
	*adminClient.Acp
}

type Developer struct {
	*developerClient.Acp
}

type Public struct {
	*publicClient.Acp
}

type System struct {
	*systemClient.Acp
}

type Web struct {
	*webClient.Acp
}

type Root struct {
	*rootClient.Acp
}

type Fdx struct {
	*fdx.Acp
}

type Cdr struct {
	*cdr.Acp
}

type Obuk struct {
	*obuk.Acp
}

type Obbr struct {
	*obbr.Acp
}

type Opin struct {
	*opin.Acp
}

type Ksa struct {
	*ksa.Acp
}

type OpenbankingUK struct {
	Accounts *obukAccounts.OpenbankingUKClient
	Payments *obukPayments.OpenbankingUKClient
}

type OpenbankingBrasil struct {
	Consents *obbrConsents.OpenbankingBRClient
	Payments *obbrPayments.OpenbankingBRClient
}

type Identity struct {
	*identity.Acp
}

type IdentitySelf struct {
	*identityself.Acp
}

type IdentityRoot struct {
	*identityroot.Acp
}

type IdentitySystem struct {
	*identitysystem.Acp
}

type LicensingRoot struct {
	*licensingroot.Acp
}

type LicensingAdmin struct {
	*licensingadmin.Acp
}

type Hub struct {
	*hub.Acp
}

// Client provides a client to the ACP API
type Client struct {
	Oauth2    *Oauth2
	Admin     *Admin
	Developer *Developer
	Public    *Public
	System    *System
	Web       *Web
	Root      *Root
	Fdx       *Fdx
	Cdr       *Cdr
	Obuk      *Obuk
	Obbr      *Obbr
	Opin      *Opin
	Ksa       *Ksa
	Hub       *Hub

	*OpenbankingUK
	*OpenbankingBrasil

	Identity       *Identity
	IdentitySelf   *IdentitySelf
	IdentityRoot   *IdentityRoot
	IdentitySystem *IdentitySystem

	LicensingRoot  *LicensingRoot
	LicensingAdmin *LicensingAdmin

	c                          *http.Client
	requestObjectSigningKey    interface{}
	requestObjectEncryptionKey jose.JSONWebKey

	clientAssertionSigningKey interface{}

	// Client configuration
	Config Config

	// Tenant id read from the IssuerURL
	TenantID string

	// Authorization server id read from the IssuerURL
	ServerID string

	// Base path read from the IssuerURL
	BasePath string
}

type AuthMethod string

const (
	ClientSecretBasicAuthnMethod AuthMethod = "client_secret_basic"
	ClientSecretPostAuthnMethod  AuthMethod = "client_secret_post"
	ClientSecretJwtAuthnMethod   AuthMethod = "client_secret_jwt"
	PrivateKeyJwtAuthnMethod     AuthMethod = "private_key_jwt"
	SelfSignedTLSAuthnMethod     AuthMethod = "self_signed_tls_client_auth"
	TLSClientAuthnMethod         AuthMethod = "tls_client_auth"
	NoneAuthnMethod              AuthMethod = "none"
)

// ACP client configuration
type Config struct {
	// ClientID is the application's ID.
	ClientID string `json:"client_id"`

	// AuthMethod represents how requests for tokens are authenticated to the server.
	AuthMethod AuthMethod

	// ClientSecret is the application's secret.
	ClientSecret string `json:"client_secret"`

	// RedirectURL is the URL to redirect users after authentication.
	RedirectURL *url.URL `json:"redirect_url"`

	// IssuerURL is the authorization server's url.
	// example: https://localhost:8443/default/default
	IssuerURL *url.URL `json:"issuer_url"`

	// TokenURL is the authorization server's token url.
	// Optional if issuerURL provided
	TokenURL *url.URL

	// AuthorizeURL is the authorization server's authorize url.
	// Optional if issuerURL provided
	AuthorizeURL *url.URL

	// PushedAuthorizationRequestEndpoint is URL of the pushed authorization request endpoint
	// at which a client can post an authorization request to exchange
	// for a "request_uri" value usable at the authorization server.
	PushedAuthorizationRequestEndpoint *url.URL

	// UserinfoURL is the authorization server's userinfo url.
	// Optional if issuerURL provided
	UserinfoURL *url.URL

	// Scope specifies optional requested permissions.
	Scopes []string `json:"scopes"`

	// Path to the file with private key for signing request object.
	RequestObjectSigningKeyFile string `json:"request_object_signing_key_file"`

	// Request object signing algorithm
	// If empty RS256 will be used
	RequestObjectSigningAlg string `json:"request_object_signing_alg"`

	// Path to the file with private key for private_key_jwt token authentication
	ClientAssertionSigningKeyFile string `json:"client_assertion_signing_key_file"`

	// Client assertion signing algorithm
	// If empty RS256 will be used
	ClientAssertionSigningAlg string `json:"client_assertion_signing_alg"`

	// Path to the file with private key for encrypting request object.
	RequestObjectEncryptionKeyFile string `json:"request_object_encryption_key_file"`

	// Optional request object expiration time
	// If not provided, it will be se to 1 minute
	RequestObjectExpiration *time.Duration `json:"request_object_expiration"`

	// Default HttpClient timeout.
	// Ignored if HttpClient is provided.
	Timeout time.Duration `json:"timeout"`

	// Optional path to the file with certificate for tls authentication.
	// Ignored if HttpClient is provided.
	CertFile string `json:"cert_file"`

	// Optional path to the file with private key for tls authentication.
	// Ignored if HttpClient is provided.
	KeyFile string `json:"key_file"`

	// Optional path to the file with root CAs.
	// Ignored if HttpClient is provided.
	RootCA string `json:"root_ca"`

	// HttpClient is the client to use. Default will be used if not provided.
	HttpClient *http.Client `json:"-"`

	// Optional vanity domain type, one of "", "tenant" or "server".
	VanityDomainType string `json:"vanity_domain_type"`

	// Tenant id required when VanityDomainType is "tenant" or "server"
	TenantID string `json:"tenant_id"`

	// Authorization server id required when VanityDomainType is "server".
	ServerID string `json:"server_id"`

	// If enabled, client credentials flow won't be applied
	SkipClientCredentialsAuthn bool `json:"skip_client_credentials_authn"`
}

func (c *Config) GetTokenURL() string {
	if c.TokenURL != nil {
		return c.TokenURL.String()
	}

	return fmt.Sprintf("%s/oauth2/token", c.IssuerURL.String())
}

func (c *Config) GetAuthorizeURL() string {
	if c.AuthorizeURL != nil {
		return c.AuthorizeURL.String()
	}

	return fmt.Sprintf("%s/oauth2/authorize", c.IssuerURL.String())
}

func (c *Config) GetPARURL() string {
	if c.PushedAuthorizationRequestEndpoint != nil {
		return c.PushedAuthorizationRequestEndpoint.String()
	}

	return fmt.Sprintf("%s/par", c.IssuerURL.String())
}

func (c *Config) GetUserinfoURL() string {
	if c.UserinfoURL != nil {
		return c.UserinfoURL.String()
	}

	return fmt.Sprintf("%s/userinfo", c.IssuerURL.String())
}

// Determine Basepath, TenantID, and ServerID from the config.
func (c *Client) configureBasePath(cfg Config) error {
	var (
		paths   []string
		lastIdx int
	)
	switch cfg.VanityDomainType {
	case "":
		paths = strings.Split(cfg.IssuerURL.Path, "/")
		if len(paths) < 3 {
			return errors.New("invalid issuer url")
		}
		lastIdx = len(paths) - 1

		c.TenantID = paths[lastIdx-1]
		c.ServerID = paths[lastIdx]
		c.BasePath = strings.Join(paths[:lastIdx-1], "/")

	case "tenant":
		if cfg.TenantID == "" {
			return errors.New("Config.TenantID is required when RouterType is \"tenant\"")
		}
		paths = strings.Split(cfg.IssuerURL.Path, "/")
		if len(paths) < 2 {
			return errors.New("invalid issuer url")
		}
		lastIdx = len(paths) - 1

		c.TenantID = cfg.TenantID
		c.ServerID = paths[lastIdx]
		c.BasePath = strings.Join(paths[:lastIdx], "/")

	case "server":
		if cfg.TenantID == "" {
			return errors.New("Config.TenantID is required when RouterType is \"server\"")
		}
		if cfg.ServerID == "" {
			return errors.New("Config.ServerID is required when RouterType is \"server\"")
		}

		c.TenantID = cfg.TenantID
		c.ServerID = cfg.ServerID
		c.BasePath = cfg.IssuerURL.Path

	default:
		return errors.New("Config.RouterType must be one of \"\", \"tenant\", or \"server\"")
	}

	if c.BasePath == "/" {
		c.BasePath = ""
	}
	return nil
}

func (c *Client) discoverEndpoints(issuerURL string) error {
	var (
		b             []byte
		wellKnown     o2models.WellKnown
		resp          *http.Response
		tokenEndpoint string
		err           error
	)

	if resp, err = c.c.Get(fmt.Sprintf("%s/.well-known/openid-configuration", issuerURL)); err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if b, err = io.ReadAll(resp.Body); err != nil {
			return errors.WithMessagef(err, "unable to read response body from well-known endpoint with status %d", resp.StatusCode)
		}
		return errors.WithMessage(errors.New(string(b)), "unable to get well-known endpoints")
	}

	if err = json.NewDecoder(resp.Body).Decode(&wellKnown); err != nil {
		return err
	}

	tokenEndpoint = wellKnown.TokenEndpoint
	if c.Config.CertFile != "" && c.Config.KeyFile != "" {
		if wellKnown.MtlsEndpointAliases != nil && wellKnown.MtlsEndpointAliases.TokenEndpoint != "" {
			tokenEndpoint = wellKnown.MtlsEndpointAliases.TokenEndpoint
		}
	}

	if c.Config.TokenURL, err = url.Parse(tokenEndpoint); err != nil {
		return err
	}

	if c.Config.AuthorizeURL, err = url.Parse(wellKnown.AuthorizationEndpoint); err != nil {
		return err
	}

	if c.Config.PushedAuthorizationRequestEndpoint, err = url.Parse(wellKnown.PushedAuthorizationRequestEndpoint); err != nil {
		return err
	}

	if c.Config.UserinfoURL, err = url.Parse(wellKnown.UserinfoEndpoint); err != nil {
		return err
	}

	return nil
}

func (c *Config) newHTTPClient() (*http.Client, error) {
	var (
		pool  *x509.CertPool
		cert  tls.Certificate
		certs = []tls.Certificate{}
		data  []byte
		err   error
	)

	if c.CertFile != "" && c.KeyFile != "" {
		if cert, err = tls.LoadX509KeyPair(c.CertFile, c.KeyFile); err != nil {
			return nil, errors.Wrapf(err, "failed to read certificate and private key")
		}

		certs = append(certs, cert)
	}

	if pool, err = x509.SystemCertPool(); err != nil {
		return nil, errors.Wrapf(err, "failed to read system root CAs")
	}

	if c.RootCA != "" {
		if data, err = os.ReadFile(c.RootCA); err != nil {
			return nil, fmt.Errorf("failed to read http client root ca: %w", err)
		}

		pool.AppendCertsFromPEM(data)
	}

	return &http.Client{
		Timeout: c.Timeout,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			ResponseHeaderTimeout: c.Timeout,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			MaxIdleConnsPerHost:   runtime.GOMAXPROCS(0) + 1,
			TLSClientConfig: &tls.Config{
				RootCAs:      pool,
				MinVersion:   tls.VersionTLS12,
				Certificates: certs,
			},
		},
	}, nil
}

// Create a new ACP client instance based on config.
func New(cfg Config) (c Client, err error) {
	if cfg.ClientID == "" {
		return c, errors.New("client_id is missing")
	}

	if cfg.IssuerURL == nil {
		return c, errors.New("issuer_url is missing")
	}

	if (cfg.AuthMethod == ClientSecretPostAuthnMethod || cfg.AuthMethod == ClientSecretBasicAuthnMethod) && cfg.ClientSecret == "" {
		return c, errors.New("client_secret is missing")
	}

	if cfg.ClientAssertionSigningAlg == "" {
		cfg.ClientAssertionSigningAlg = "RS256"
	}

	if cfg.RequestObjectSigningAlg == "" {
		cfg.RequestObjectSigningAlg = "RS256"
	}

	// Configure BasePath, TenantID and ServerID from the Config.
	if err = c.configureBasePath(cfg); err != nil {
		return c, err
	}

	if cfg.HttpClient == nil {
		if c.c, err = cfg.newHTTPClient(); err != nil {
			return c, err
		}
	} else {
		c.c = cfg.HttpClient
	}

	if err = c.discoverEndpoints(cfg.IssuerURL.String()); err != nil {
		return c, err
	}

	if cfg.RequestObjectSigningKeyFile != "" {
		if c.requestObjectSigningKey, err = loadSigningKeyFromFile(cfg.RequestObjectSigningKeyFile); err != nil {
			return c, errors.Wrapf(err, "failed to load request object signing key file")
		}
	}

	if cfg.ClientAssertionSigningKeyFile != "" {
		if c.clientAssertionSigningKey, err = loadSigningKeyFromFile(cfg.ClientAssertionSigningKeyFile); err != nil {
			return c, errors.Wrapf(err, "failed to load client assertion signing key file")
		}
	}

	if cfg.RequestObjectEncryptionKeyFile != "" {
		var bs []byte

		if bs, err = os.ReadFile(cfg.RequestObjectEncryptionKeyFile); err != nil {
			return c, errors.Wrapf(err, "failed to read request object encryption key")
		}

		if err = c.requestObjectEncryptionKey.UnmarshalJSON(bs); err != nil {
			return c, errors.Wrapf(err, "failed to parse request object encryption key")
		}
	}

	client := c.c

	if !cfg.SkipClientCredentialsAuthn {
		client = NewAuthenticator(clientcredentials.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Scopes:       cfg.Scopes,
			TokenURL:     cfg.GetTokenURL(),
		}, c.c)
	}

	c.Oauth2 = &Oauth2{
		Acp: o2Client.New(httptransport.NewWithClient(
			cfg.IssuerURL.Host,
			c.apiPathPrefix(cfg.VanityDomainType, "/%s/%s"),
			[]string{cfg.IssuerURL.Scheme},
			client,
		).WithOpenTracing(), nil),
	}

	c.Admin = &Admin{
		Acp: adminClient.New(httptransport.NewWithClient(
			cfg.IssuerURL.Host,
			c.apiPathPrefix(cfg.VanityDomainType, "/api/admin/%s"),
			[]string{cfg.IssuerURL.Scheme},
			client,
		).WithOpenTracing(), nil),
	}

	c.Developer = &Developer{
		Acp: developerClient.New(httptransport.NewWithClient(
			cfg.IssuerURL.Host,
			c.apiPathPrefix(cfg.VanityDomainType, "/api/developer/%s/%s"),
			[]string{cfg.IssuerURL.Scheme},
			client,
		).WithOpenTracing(), nil),
	}

	c.Public = &Public{
		Acp: publicClient.New(httptransport.NewWithClient(
			cfg.IssuerURL.Host,
			c.apiPathPrefix(cfg.VanityDomainType, "/%s/%s"),
			[]string{cfg.IssuerURL.Scheme},
			client,
		).WithOpenTracing(), nil),
	}

	c.Root = &Root{
		Acp: rootClient.New(httptransport.NewWithClient(
			cfg.IssuerURL.Host,
			c.BasePath,
			[]string{cfg.IssuerURL.Scheme},
			client,
		).WithOpenTracing(), nil),
	}

	c.System = &System{
		Acp: systemClient.New(httptransport.NewWithClient(
			cfg.IssuerURL.Host,
			c.apiPathPrefix(cfg.VanityDomainType, "/api/system/%s"),
			[]string{cfg.IssuerURL.Scheme},
			client,
		).WithOpenTracing(), nil),
	}

	c.Web = &Web{
		Acp: webClient.New(httptransport.NewWithClient(
			cfg.IssuerURL.Host,
			c.apiPathPrefix(cfg.VanityDomainType, "/%s/%s"),
			[]string{cfg.IssuerURL.Scheme},
			client,
		).WithOpenTracing(), nil),
	}

	apiPrefix := c.apiPathPrefix(cfg.VanityDomainType, "/%s/%s")

	c.OpenbankingUK = &OpenbankingUK{
		Accounts: obukAccounts.New(httptransport.NewWithClient(
			cfg.IssuerURL.Host,
			apiPrefix+obukAccounts.DefaultBasePath,
			[]string{cfg.IssuerURL.Scheme},
			client,
		).WithOpenTracing(), nil),

		Payments: obukPayments.New(httptransport.NewWithClient(
			cfg.IssuerURL.Host,
			apiPrefix+obukPayments.DefaultBasePath,
			[]string{cfg.IssuerURL.Scheme},
			client,
		).WithOpenTracing(), nil),
	}

	obbrPaymentsTransport := httptransport.NewWithClient(
		cfg.IssuerURL.Host,
		apiPrefix+obbrPayments.DefaultBasePath,
		[]string{cfg.IssuerURL.Scheme},
		client,
	)
	obbrPaymentsTransport.Consumers["application/jwt"] = &JWTConsumer{}

	c.OpenbankingBrasil = &OpenbankingBrasil{
		Consents: obbrConsents.New(httptransport.NewWithClient(
			cfg.IssuerURL.Host,
			apiPrefix+obbrConsents.DefaultBasePath,
			[]string{cfg.IssuerURL.Scheme},
			client,
		).WithOpenTracing(), nil),

		Payments: obbrPayments.New(obbrPaymentsTransport.WithOpenTracing(), nil),
	}

	openbankingTransport := httptransport.NewWithClient(
		cfg.IssuerURL.Host,
		c.apiPathPrefix(cfg.VanityDomainType, "/%s/%s"),
		[]string{cfg.IssuerURL.Scheme},
		client,
	)
	openbankingTransport.Consumers["application/jwt"] = &JWTConsumer{}

	c.Fdx = &Fdx{
		Acp: &fdx.Acp{
			Fdx:         fdxfdx.New(openbankingTransport.WithOpenTracing(), nil),
			Consentpage: fdxconsentpage.New(openbankingTransport.WithOpenTracing(), nil),
			Dcr:         fdxdcr.New(openbankingTransport.WithOpenTracing(), nil),
			Management:  fdxmanagement.New(openbankingTransport.WithOpenTracing(), nil),
		},
	}

	c.Cdr = &Cdr{
		Acp: &cdr.Acp{
			Cdr:         cdrcdr.New(openbankingTransport.WithOpenTracing(), nil),
			Consentpage: cdrconsentpage.New(openbankingTransport.WithOpenTracing(), nil),
			Dcr:         cdrdcr.New(openbankingTransport.WithOpenTracing(), nil),
			Management:  cdrmanagement.New(openbankingTransport.WithOpenTracing(), nil),
		},
	}

	c.Obbr = &Obbr{
		Acp: &obbr.Acp{
			Obbr:        obbrobbr.New(openbankingTransport.WithOpenTracing(), nil),
			Consentpage: obbrconsentpage.New(openbankingTransport.WithOpenTracing(), nil),
			Dcr:         obbrdcr.New(openbankingTransport.WithOpenTracing(), nil),
			Management:  obbrmanagement.New(openbankingTransport.WithOpenTracing(), nil),
		},
	}

	c.Obuk = &Obuk{
		Acp: &obuk.Acp{
			Obuk:        obukobuk.New(openbankingTransport.WithOpenTracing(), nil),
			Consentpage: obukconsentpage.New(openbankingTransport.WithOpenTracing(), nil),
			Dcr:         obukdcr.New(openbankingTransport.WithOpenTracing(), nil),
			Management:  obukmanagement.New(openbankingTransport.WithOpenTracing(), nil),
		},
	}

	c.Opin = &Opin{
		Acp: &opin.Acp{
			Opin: opinopin.New(openbankingTransport.WithOpenTracing(), nil),
		},
	}

	c.Ksa = &Ksa{
		Acp: &ksa.Acp{
			Consentpage: ksaconsentpage.New(openbankingTransport.WithOpenTracing(), nil),
		},
	}

	c.Identity = &Identity{
		Acp: identity.New(httptransport.NewWithClient(
			cfg.IssuerURL.Host,
			c.apiPathPrefix(cfg.VanityDomainType, "/api/identity/%s"),
			[]string{cfg.IssuerURL.Scheme},
			client,
		).WithOpenTracing(), nil),
	}

	c.IdentitySelf = &IdentitySelf{
		Acp: identityself.New(httptransport.NewWithClient(
			cfg.IssuerURL.Host,
			c.apiPathPrefix(cfg.VanityDomainType, "/%s/%s/identity"),
			[]string{cfg.IssuerURL.Scheme},
			client,
		).WithOpenTracing(), nil),
	}

	c.IdentityRoot = &IdentityRoot{
		Acp: identityroot.New(httptransport.NewWithClient(
			cfg.IssuerURL.Host,
			c.apiPathPrefix(cfg.VanityDomainType, "/api/identity/%s"),
			[]string{cfg.IssuerURL.Scheme},
			client,
		).WithOpenTracing(), nil),
	}

	c.IdentitySystem = &IdentitySystem{
		Acp: identitysystem.New(httptransport.NewWithClient(
			cfg.IssuerURL.Host,
			c.apiPathPrefix(cfg.VanityDomainType, "/api/identity/%s"),
			[]string{cfg.IssuerURL.Scheme},
			client,
		).WithOpenTracing(), nil),
	}

	c.LicensingAdmin = &LicensingAdmin{
		Acp: licensingadmin.New(httptransport.NewWithClient(
			cfg.IssuerURL.Host,
			c.apiPathPrefix(cfg.VanityDomainType, "/api/licensing/%s"),
			[]string{cfg.IssuerURL.Scheme},
			client,
		).WithOpenTracing(), nil),
	}

	c.LicensingRoot = &LicensingRoot{
		Acp: licensingroot.New(httptransport.NewWithClient(
			cfg.IssuerURL.Host,
			c.apiPathPrefix(cfg.VanityDomainType, "/api/licensing/%s"),
			[]string{cfg.IssuerURL.Scheme},
			client,
		).WithOpenTracing(), nil),
	}

	c.Hub = &Hub{
		Acp: hub.New(httptransport.NewWithClient(
			cfg.IssuerURL.Host,
			"/api/hub",
			[]string{cfg.IssuerURL.Scheme},
			client,
		).WithOpenTracing(), nil),
	}

	c.Config = cfg

	return c, nil
}

// apiPathPrefix adjusts the default API path prefixes to work with vanity domains.
func (c *Client) apiPathPrefix(vanityDomainType string, format string) string {
	switch format {
	case "/api/admin/%s":
		switch vanityDomainType {
		case "tenant", "server":
			return c.BasePath + "/api/admin"
		default:
			return c.BasePath + fmt.Sprintf(format, c.TenantID)
		}

	case "/api/developer/%s/%s":
		switch vanityDomainType {
		case "server":
			return c.BasePath + "/api/developer"
		case "tenant":
			return c.BasePath + "/api/developer/" + c.ServerID
		default:
			return c.BasePath + fmt.Sprintf(format, c.TenantID, c.ServerID)
		}

	case "/api/system/%s":
		switch vanityDomainType {
		case "tenant", "server":
			return c.BasePath + "/api/system"
		default:
			return c.BasePath + fmt.Sprintf(format, c.TenantID)
		}

	case "/api/identity/%s":
		switch vanityDomainType {
		case "tenant", "server":
			return c.BasePath + "/api/identity"
		default:
			return c.BasePath + fmt.Sprintf(format, c.TenantID)
		}

	case "/api/identity/system/%s":
		switch vanityDomainType {
		case "tenant", "server":
			return c.BasePath + "/api/identity/system"
		default:
			return c.BasePath + fmt.Sprintf(format, c.TenantID)
		}

	case "/%s/%s":
		switch vanityDomainType {
		case "server":
			return c.BasePath
		case "tenant":
			return c.BasePath + "/" + c.ServerID
		default:
			return c.BasePath + fmt.Sprintf(format, c.TenantID, c.ServerID)
		}

	default:
		return c.BasePath + fmt.Sprintf(format, c.TenantID, c.ServerID)
	}
}

type Token struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    int    `json:"expires_in"`
	GrantID      string `json:"grant_id,omitempty"`
}

// CSRF contains state, nonce and/or PKCEverifier which are used
// to mitigate replay attacks and cross-site request forgery.
type CSRF struct {
	// State is an opaque value used by the client to maintain
	// state between the request and callback.  The authorization
	// server includes this value when redirecting the user-agent back
	// to the client.  The parameter SHOULD be used for preventing
	// cross-site request forgery
	State string

	// Nonce is a string value used to associate a client session with
	// an ID Token, and to mitigate replay attacks
	Nonce string

	// PKCE code verifier
	Verifier string
}

func NewCSRF() (csrf CSRF, err error) {
	if csrf.State, err = randomString(StateLength); err != nil {
		return csrf, err
	}

	if csrf.Nonce, err = randomString(NonceLength); err != nil {
		return csrf, err
	}
	return csrf, err
}

type ClaimRequests struct {
	Userinfo map[string]*ClaimRequest `json:"userinfo"`
	IDToken  map[string]*ClaimRequest `json:"id_token"`
}

type ClaimRequest struct {
	Essential bool     `json:"essential"`
	Value     string   `json:"value"`
	Values    []string `json:"values"`
}

type AuthorizeOption interface {
	apply(*Client, url.Values, *CSRF) error
}

type authorizeOptionFn struct {
	fn func(*Client, url.Values, *CSRF) error
}

func (o *authorizeOptionFn) apply(c *Client, v url.Values, csrf *CSRF) error {
	return o.fn(c, v, csrf)
}

func authorizeHandler(fn func(*Client, url.Values, *CSRF) error) AuthorizeOption {
	return &authorizeOptionFn{fn: fn}
}

func WithAuthorizationDetails(authorizationDetails string) AuthorizeOption {
	return authorizeHandler(func(c *Client, v url.Values, csrf *CSRF) (err error) {
		v.Set("authorization_details", authorizationDetails)
		return nil
	})
}

func WithResponseType(responseTypes ...string) AuthorizeOption {
	return authorizeHandler(func(c *Client, v url.Values, csrf *CSRF) (err error) {
		v.Set("response_type", strings.Join(responseTypes, " "))
		return nil
	})
}

func WithResponseMode(responseMode string) AuthorizeOption {
	return authorizeHandler(func(c *Client, v url.Values, csrf *CSRF) (err error) {
		v.Set("response_mode", responseMode)
		return nil
	})
}

func WithPAR(clientID string, requestURI string) AuthorizeOption {
	return authorizeHandler(func(c *Client, v url.Values, csrf *CSRF) (err error) {
		v.Set("client_id", clientID)
		v.Set("request_uri", requestURI)
		return nil
	})
}

func WithPKCE() AuthorizeOption {
	return authorizeHandler(func(c *Client, v url.Values, csrf *CSRF) (err error) {
		if csrf.Verifier, err = randomString(VerifierLength); err != nil {
			return errors.Wrapf(err, "failed to generate random verifier for PKCE authentication")
		}

		hash := sha256.New()

		if _, err = hash.Write([]byte(csrf.Verifier)); err != nil {
			return errors.Wrapf(err, "failed to hash PKCE verifier")
		}

		v.Set("code_challenge", base64.RawURLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash.Sum([]byte{})))
		v.Set("code_challenge_method", "S256")

		return nil
	})
}

func WithRequestObjectEncryption(key jose.JSONWebKey) AuthorizeOption {
	return authorizeHandler(func(c *Client, v url.Values, csrf *CSRF) error {
		var (
			encryptedToken string
			encrypter      jose.Encrypter
			jwe            *jose.JSONWebEncryption
			token          = v.Get("request")
			err            error
		)

		if encrypter, err = jose.NewEncrypter(jose.A256GCM, jose.Recipient{
			Algorithm: jose.KeyAlgorithm(key.Algorithm),
			Key:       key.Key,
		}, &jose.EncrypterOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				jose.HeaderContentType: "jwt",
			},
		}); err != nil {
			return errors.Wrapf(err, "failed to create request object encrypter")
		}

		if jwe, err = encrypter.Encrypt([]byte(token)); err != nil {
			return errors.Wrapf(err, "failed to encrypt request object")
		}

		if encryptedToken, err = jwe.CompactSerialize(); err != nil {
			return errors.Wrapf(err, "failed to serialize encrypted request object")
		}

		v.Set("request", encryptedToken)

		return nil
	})
}

func WithOpenbankingIntentID(intentID string, acr []string) AuthorizeOption {
	return authorizeHandler(func(c *Client, v url.Values, csrf *CSRF) error {
		var (
			acrClaimRequest = ClaimRequest{
				Essential: true,
			}
		)

		if len(acr) == 1 {
			acrClaimRequest.Value = acr[0]
		} else {
			acrClaimRequest.Values = acr
		}

		claims := getOpenbankingClaims(c.Config, csrf)

		claims["claims"] = ClaimRequests{
			Userinfo: map[string]*ClaimRequest{
				"openbanking_intent_id": {
					Essential: true,
					Value:     intentID,
				},
			},
			IDToken: map[string]*ClaimRequest{
				"openbanking_intent_id": {
					Essential: true,
					Value:     intentID,
				},
				"acr": &acrClaimRequest,
			},
		}

		return WithSignedRequestObject(claims).apply(c, v, csrf)
	})
}

func WithOpenbankingACR(acr []string) AuthorizeOption {
	return authorizeHandler(func(c *Client, v url.Values, csrf *CSRF) error {
		var (
			acrClaimRequest = ClaimRequest{
				Essential: true,
			}
		)

		if len(acr) == 1 {
			acrClaimRequest.Value = acr[0]
		} else {
			acrClaimRequest.Values = acr
		}

		claims := getOpenbankingClaims(c.Config, csrf)
		claims["claims"] = ClaimRequests{
			IDToken: map[string]*ClaimRequest{
				"acr": &acrClaimRequest,
			},
		}

		return WithSignedRequestObject(claims).apply(c, v, csrf)
	})
}

func getOpenbankingClaims(config Config, csrf *CSRF) jwt.MapClaims {
	var (
		requestObjectExpiration = time.Minute
	)

	if config.RequestObjectExpiration != nil {
		requestObjectExpiration = *config.RequestObjectExpiration
	}

	claims := jwt.MapClaims{
		"exp":   time.Now().Add(requestObjectExpiration).Unix(),
		"nonce": csrf.Nonce,
		"state": csrf.State,
		"nbf":   time.Now().Unix(),
	}

	if config.RedirectURL != nil {
		claims["redirect_uri"] = config.RedirectURL.String()
	}

	if len(config.Scopes) > 0 {
		claims["scope"] = strings.Join(config.Scopes, " ")
	}

	return claims
}

func WithSignedRequestObject(claims jwt.MapClaims) AuthorizeOption {
	return authorizeHandler(func(c *Client, v url.Values, csrf *CSRF) error {
		var (
			signedToken string
			method      jwt.SigningMethod
			err         error
		)

		if method, err = getSigningMethod(c.Config.RequestObjectSigningAlg); err != nil {
			return errors.Wrapf(err, "failed to get signing method for request object")
		}

		token := jwt.NewWithClaims(method, claims)

		if signedToken, err = token.SignedString(c.requestObjectSigningKey); err != nil {
			return errors.Wrapf(err, "failed to sign openbanking request object")
		}

		v.Set("request", signedToken)
		return nil
	})
}

func (c *Client) AuthorizeURLWithPAR(requestURI string) (authorizeURL string, err error) {
	values := url.Values{
		"client_id":   {c.Config.ClientID},
		"request_uri": {requestURI},
	}
	return fmt.Sprintf("%s?%s", c.Config.GetAuthorizeURL(), values.Encode()), nil
}

func (c *Client) AuthorizeURL(options ...AuthorizeOption) (authorizeURL string, csrf CSRF, err error) {
	var (
		values url.Values
	)

	if values, csrf, err = c.preapreValues(); err != nil {
		return authorizeURL, csrf, fmt.Errorf("failed to prepare values for Authorize URL: %w", err)
	}

	for _, o := range options {
		if err = o.apply(c, values, &csrf); err != nil {
			return authorizeURL, csrf, err
		}
	}

	return fmt.Sprintf("%s?%s", c.Config.GetAuthorizeURL(), values.Encode()), csrf, nil
}

func (c *Client) GenerateClientAssertion() (assertion string, err error) {
	var method jwt.SigningMethod

	if method, err = getSigningMethod(c.Config.ClientAssertionSigningAlg); err != nil {
		return "", errors.Wrapf(err, "failed to get signing method for client assertion")
	}

	claims := jwt.MapClaims{
		"iss": c.Config.ClientID,
		"sub": c.Config.ClientID,
		"aud": c.Config.GetTokenURL(),
		"jti": uuid.New().String(),
		"exp": time.Now().Add(time.Minute * 5).Unix(),
	}

	return jwt.NewWithClaims(method, claims).SignedString(c.clientAssertionSigningKey)
}

type PARResponse struct {
	ExpiresIn  int64  `json:"expires_in,omitempty"`
	RequestURI string `json:"request_uri,omitempty"`
}

func (c *Client) DoPAR(options ...AuthorizeOption) (pr PARResponse, csrf CSRF, err error) {
	var (
		values  url.Values
		request *http.Request
	)

	if values, csrf, err = c.preapreValues(); err != nil {
		return pr, csrf, fmt.Errorf("failed to prepare values for PAR request: %w", err)
	}

	if request, err = c.prepareRequest(c.Config.GetPARURL(), values, &csrf, options...); err != nil {
		return pr, csrf, fmt.Errorf("failed to prepare PAR request: %w", err)
	}

	if err = c.getResponse(request, http.StatusCreated, &pr); err != nil {
		return pr, csrf, fmt.Errorf("failed to do PAR request: %w", err)
	}

	return pr, csrf, nil
}

func (c *Client) Exchange(code string, state string, csrf CSRF) (token Token, err error) {
	var (
		request *http.Request
	)
	values := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"client_id":    {c.Config.ClientID},
		"redirect_uri": {c.Config.RedirectURL.String()},
	}

	if csrf.Verifier != "" {
		values.Set("code_verifier", csrf.Verifier)
	}

	if request, err = c.prepareRequest(c.Config.GetTokenURL(), values, &csrf); err != nil {
		return token, fmt.Errorf("failed to prepare exchange token request: %w", err)
	}

	if err = c.getResponse(request, http.StatusOK, &token); err != nil {
		return token, fmt.Errorf("failed to do exchange token request: %w", err)
	}

	if state != csrf.State {
		return token, errors.New("invalid state")
	}
	// TODO check nonce

	return token, nil
}

func (c *Client) Userinfo(token string) (body map[string]interface{}, err error) {
	var (
		request *http.Request
	)

	if request, err = http.NewRequest("GET", c.Config.GetUserinfoURL(), nil); err != nil {
		return body, fmt.Errorf("failed to build userinfo request: %w", err)
	}
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))

	if err = c.getResponse(request, http.StatusOK, &body); err != nil {
		return body, fmt.Errorf("failed to get userinfo: %w", err)
	}

	return body, nil
}

func (c *Client) preapreValues() (values url.Values, csrf CSRF, err error) {
	if csrf, err = NewCSRF(); err != nil {
		return values, csrf, fmt.Errorf("failed to generate CSRF for PAR: %w", err)
	}

	values = url.Values{
		"client_id": {c.Config.ClientID},
		"nonce":     {csrf.Nonce},
		"state":     {csrf.State},
	}

	if c.Config.RedirectURL != nil {
		values.Set("redirect_uri", c.Config.RedirectURL.String())
	}

	if len(c.Config.Scopes) > 0 {
		values.Set("scope", strings.Join(c.Config.Scopes, " "))
	}

	return values, csrf, err
}

func (c *Client) prepareRequest(requestURL string, values url.Values, csrf *CSRF, options ...AuthorizeOption) (request *http.Request, err error) {
	if c.Config.AuthMethod == ClientSecretPostAuthnMethod {
		values.Add("client_secret", c.Config.ClientSecret)
	}

	if c.Config.AuthMethod == PrivateKeyJwtAuthnMethod {
		var (
			assertion string
		)
		values.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		if assertion, err = c.GenerateClientAssertion(); err != nil {
			return request, errors.Wrapf(err, "failed to generate client assertion")
		}
		values.Add("client_assertion", assertion)
	}

	for _, o := range options {
		if err = o.apply(c, values, csrf); err != nil {
			return request, err
		}
	}

	if request, err = http.NewRequest(http.MethodPost, requestURL, strings.NewReader(values.Encode())); err != nil {
		return request, fmt.Errorf("failed to build request for token exchange: %w", err)
	}

	if c.Config.AuthMethod == ClientSecretBasicAuthnMethod {
		request.SetBasicAuth(url.QueryEscape(c.Config.ClientID), url.QueryEscape(c.Config.ClientSecret))
	}

	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	return request, err
}

func (c *Client) getResponse(request *http.Request, expectedStatusCode int, resp interface{}) (err error) {
	var (
		response *http.Response
		body     []byte
	)

	if response, err = c.c.Do(request); err != nil {
		return fmt.Errorf("failed to exchange token: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != expectedStatusCode {
		if body, err = io.ReadAll(response.Body); err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}

		return fmt.Errorf("failed to do request %d: %s", response.StatusCode, string(body))
	}

	if body, err = io.ReadAll(response.Body); err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if err = json.Unmarshal(body, resp); err != nil {
		return fmt.Errorf("failed to parse exchange response: %w", err)
	}

	return err
}

func (c *Client) IntrospectToken(ctx context.Context, token string) (*o2models.IntrospectResponse, error) {
	var (
		resp *o2Params.IntrospectOK
		err  error
	)

	if resp, err = c.Oauth2.Oauth2.Introspect(o2Params.NewIntrospectParams().
		WithContext(ctx).
		WithToken(&token), nil); err != nil {
		return nil, err
	}

	return resp.Payload, nil
}

func (c *Client) DoRequest(request *http.Request) (*http.Response, error) {
	return c.c.Do(request)
}

func randomString(length int) (string, error) {
	var (
		data = make([]byte, length)
		err  error
	)

	if _, err = io.ReadFull(rand.Reader, data); err != nil {
		return "", errors.Wrapf(err, "failed to generate random string")
	}

	return base64.RawURLEncoding.WithPadding(base64.NoPadding).EncodeToString(data), nil
}

func loadSigningKeyFromFile(path string) (key interface{}, err error) {
	var bs []byte

	if bs, err = os.ReadFile(path); err != nil {
		return key, errors.Wrapf(err, "failed to read signing key")
	}

	block, _ := pem.Decode(bs)

	if key, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		return key, errors.Wrapf(err, "failed to parse signing key")
	}

	return key, nil
}

func getSigningMethod(alg string) (jwt.SigningMethod, error) {
	switch alg {
	case "RS256":
		return jwt.SigningMethodRS256, nil
	case "ES256":
		return jwt.SigningMethodES256, nil
	case "PS256":
		return jwt.SigningMethodPS256, nil
	default:
		return nil, fmt.Errorf("unsupported signing alg: %s", alg)
	}
}
