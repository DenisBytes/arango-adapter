package arangoadapter

import (
	"crypto/tls"
	"crypto/x509"
	"os"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/arangodb/go-driver/v2/connection"
	"golang.org/x/net/http2"
)

// Config holds the configuration for connecting to ArangoDB.
type Config struct {
	Endpoints      []string // ArangoDB endpoints (e.g., ["http://localhost:8529"])
	Username       string   // Database username
	Password       string   // Database password
	DatabaseName   string   // Name of the database to use
	CollectionName string   // Name of the collection for Casbin rules
	TLSEnabled     bool     // Whether to use TLS
	CACertPath     string   // Path to CA certificate file (for TLS)
	TLSConfig      *tls.Config // Custom TLS configuration (optional)
}

// Option is a functional option for configuring the adapter.
type Option func(*Config)

// WithEndpoints sets the ArangoDB endpoints.
func WithEndpoints(endpoints ...string) Option {
	return func(c *Config) {
		c.Endpoints = endpoints
	}
}

// WithAuthentication sets the username and password.
func WithAuthentication(username, password string) Option {
	return func(c *Config) {
		c.Username = username
		c.Password = password
	}
}

// WithDatabase sets the database name.
func WithDatabase(name string) Option {
	return func(c *Config) {
		c.DatabaseName = name
	}
}

// WithCollection sets the collection name for Casbin rules.
func WithCollection(name string) Option {
	return func(c *Config) {
		c.CollectionName = name
	}
}

// WithTLS enables TLS and optionally sets a CA certificate path.
func WithTLS(caCertPath string) Option {
	return func(c *Config) {
		c.TLSEnabled = true
		c.CACertPath = caCertPath
	}
}

// WithTLSConfig sets a custom TLS configuration.
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(c *Config) {
		c.TLSEnabled = true
		c.TLSConfig = tlsConfig
	}
}

// NewConfig creates a default configuration.
func NewConfig(opts ...Option) *Config {
	cfg := &Config{
		Endpoints:      []string{"http://localhost:8529"},
		Username:       "root",
		Password:       "",
		DatabaseName:   defaultDatabaseName,
		CollectionName: defaultCollectionName,
		TLSEnabled:     false,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	return cfg
}

// createConnection builds an ArangoDB connection from the config.
func (c *Config) createConnection() (arangodb.Client, error) {
	endpoint := connection.NewRoundRobinEndpoints(c.Endpoints)
	auth := connection.NewBasicAuth(c.Username, c.Password)

	var conn connection.Connection

	if c.TLSEnabled {
		// Use custom TLS config if provided, otherwise build from CA cert
		var tlsConfig *tls.Config
		if c.TLSConfig != nil {
			tlsConfig = c.TLSConfig
		} else if c.CACertPath != "" {
			// Load CA certificate
			caCert, err := os.ReadFile(c.CACertPath)
			if err != nil {
				return nil, err
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			tlsConfig = &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    caCertPool,
			}
		} else {
			// Default TLS config
			tlsConfig = &tls.Config{
				MinVersion: tls.VersionTLS12,
			}
		}

		// Create HTTP2 transport with TLS
		transport := &http2.Transport{
			TLSClientConfig: tlsConfig,
		}

		conn = connection.NewHttp2Connection(connection.Http2Configuration{
			Transport:      transport,
			Endpoint:       endpoint,
			Authentication: auth,
			ContentType:    "application/json",
		})
	} else {
		// Standard HTTP2 connection without TLS
		config := connection.DefaultHTTP2ConfigurationWrapper(endpoint, false)
		config.Authentication = auth
		conn = connection.NewHttp2Connection(config)
	}

	return arangodb.NewClient(conn), nil
}
