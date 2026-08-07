// Package broker implements the opt-in egress credential broker: a loopback
// MITM forward proxy that attaches vault credentials to outbound HTTPS/HTTP
// requests server-side, so a brokered secret never enters the agent's
// process environment, argv or process listing.
package broker

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

const (
	// leafTTL bounds how long a minted leaf certificate stays valid. Bounded
	// leaf lifetimes limit the exposure of a compromised CA key and force
	// clients to re-negotiate with the current configuration.
	leafTTL = 24 * time.Hour
	// caValidity is the validity of the ephemeral CA itself (one year, long
	// enough for any single broker session while still expiring).
	caValidity = 365 * 24 * time.Hour
)

// CA is an ephemeral leaf-signing certificate authority. It generates a
// self-signed CA on start and mints per-host leaf certificates with a bounded
// TTL, cached in an LRU map keyed by hostname.
type CA struct {
	mu     sync.Mutex
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	leaves map[string]leafEntry
	now    func() time.Time
}

type leafEntry struct {
	cert *tls.Certificate
	exp  time.Time
}

// NewCA generates a fresh ephemeral CA.
func NewCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "symvault egress broker (ephemeral)"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(caValidity),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	return &CA{
		caCert: caCert,
		caKey:  key,
		leaves: make(map[string]leafEntry),
		now:    time.Now,
	}, nil
}

// LeafForHost returns a cached or freshly minted leaf certificate for the
// given hostname (DNS name or IP literal), valid for leafTTL.
func (c *CA) LeafForHost(host string) (*tls.Certificate, error) {
	host = canonicalHost(host)
	if host == "" {
		return nil, fmt.Errorf("empty host")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, ok := c.leaves[host]; ok && c.now().Before(entry.exp) {
		return entry.cert, nil
	}
	cert, err := c.mintLeaf(host)
	if err != nil {
		return nil, err
	}
	c.leaves[host] = leafEntry{cert: cert, exp: c.now().Add(leafTTL)}
	return cert, nil
}

// CertPEM returns the CA certificate in PEM form, for export via
// SSL_CERT_FILE / NODE_EXTRA_CA_CERTS / REQUESTS_CA_BUNDLE.
func (c *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.caCert.Raw})
}

func (c *CA) mintLeaf(host string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	now := c.now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(leafTTL),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, c.caCert, &key.PublicKey, c.caKey)
	if err != nil {
		return nil, fmt.Errorf("create leaf certificate: %w", err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, c.caCert.Raw},
		PrivateKey:  key,
	}, nil
}

func randSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	return serial, nil
}

// canonicalHost strips the port and lowercases the hostname.
func canonicalHost(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		hostport = h
	}
	hostport = trimBrackets(hostport)
	if h := net.ParseIP(hostport); h != nil {
		return h.String()
	}
	return lowerASCII(hostport)
}

func trimBrackets(s string) string {
	if len(s) >= 2 && s[0] == '[' && s[len(s)-1] == ']' {
		return s[1 : len(s)-1]
	}
	return s
}

func lowerASCII(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
