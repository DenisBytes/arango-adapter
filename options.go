// Copyright 2024 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package arangoadapter

import (
	"crypto/tls"
	"crypto/x509"
	"os"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/arangodb/go-driver/v2/connection"
	"golang.org/x/net/http2"
)

// Config holds the connection and storage configuration for the adapter.
type Config struct {
	Endpoints      []string
	Username       string
	Password       string
	DatabaseName   string
	CollectionName string
	TLSEnabled     bool
	CACertPath     string
	TLSConfig      *tls.Config
}

// Option is a functional option for configuring the adapter.
type Option func(*Config)

// WithEndpoints sets the ArangoDB server endpoints.
func WithEndpoints(endpoints ...string) Option {
	return func(c *Config) {
		c.Endpoints = endpoints
	}
}

// WithAuthentication sets the database credentials.
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

// WithCollection sets the collection name.
func WithCollection(name string) Option {
	return func(c *Config) {
		c.CollectionName = name
	}
}

// WithTLS enables TLS with an optional CA certificate path.
func WithTLS(caCertPath string) Option {
	return func(c *Config) {
		c.TLSEnabled = true
		c.CACertPath = caCertPath
	}
}

// WithTLSConfig enables TLS with a custom tls.Config.
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(c *Config) {
		c.TLSEnabled = true
		c.TLSConfig = tlsConfig
	}
}

// NewConfig creates a Config with sensible defaults, then applies the given options.
func NewConfig(opts ...Option) *Config {
	cfg := &Config{
		Endpoints:      []string{"http://localhost:8529"},
		Username:       "root",
		Password:       "",
		DatabaseName:   defaultDatabaseName,
		CollectionName: defaultCollectionName,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	return cfg
}

func (c *Config) createConnection() (arangodb.Client, error) {
	endpoint := connection.NewRoundRobinEndpoints(c.Endpoints)
	auth := connection.NewBasicAuth(c.Username, c.Password)

	var conn connection.Connection

	if c.TLSEnabled {
		var tlsConfig *tls.Config
		if c.TLSConfig != nil {
			tlsConfig = c.TLSConfig
		} else if c.CACertPath != "" {
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
			tlsConfig = &tls.Config{
				MinVersion: tls.VersionTLS12,
			}
		}

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
		config := connection.DefaultHTTP2ConfigurationWrapper(endpoint, false)
		config.Authentication = auth
		conn = connection.NewHttp2Connection(config)
	}

	return arangodb.NewClient(conn), nil
}
