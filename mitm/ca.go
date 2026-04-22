package mitm

import (
	"container/list"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

// certCacheSize is the maximum number of leaf certificates held in memory.
// Least-recently-used entries are evicted when this limit is reached.
const certCacheSize = 256

// certCache is a fixed-capacity LRU cache for leaf TLS certificates.
// It uses a doubly-linked list to track access order and a map for O(1) lookup.
type certCache struct {
	cap   int
	items map[string]*list.Element
	ll    *list.List
}

type certEntry struct {
	host string
	cert *tls.Certificate
}

func newCertCache(cap int) *certCache {
	return &certCache{
		cap:   cap,
		items: make(map[string]*list.Element),
		ll:    list.New(),
	}
}

func (c *certCache) get(host string) (*tls.Certificate, bool) {
	el, ok := c.items[host]
	if !ok {
		return nil, false
	}
	c.ll.MoveToFront(el)
	return el.Value.(*certEntry).cert, true
}

func (c *certCache) set(host string, cert *tls.Certificate) {
	if el, ok := c.items[host]; ok {
		c.ll.MoveToFront(el)
		el.Value.(*certEntry).cert = cert
		return
	}
	if c.ll.Len() >= c.cap {
		back := c.ll.Back()
		if back != nil {
			c.ll.Remove(back)
			delete(c.items, back.Value.(*certEntry).host)
		}
	}
	el := c.ll.PushFront(&certEntry{host: host, cert: cert})
	c.items[host] = el
}

type CA struct {
	cert  *x509.Certificate
	key   *ecdsa.PrivateKey
	mu    sync.Mutex
	cache *certCache
}

func LoadOrCreateCA(certPath, keyPath string) (*CA, error) {
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		return loadCA(certPEM, keyPEM)
	}
	return generateCA(certPath, keyPath)
}

func loadCA(certPEM, keyPEM []byte) (*CA, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	return &CA{
		cert:  cert,
		key:   pair.PrivateKey.(*ecdsa.PrivateKey),
		cache: newCertCache(certCacheSize),
	}, nil
}

func generateCA(certPath, keyPath string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "impersonate-proxy CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	if err := savePEM(certPath, "CERTIFICATE", certDER); err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := savePEM(keyPath, "EC PRIVATE KEY", keyDER); err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	log.Printf("generated CA certificate → %s (add to OS trust store to avoid cert errors)", certPath)
	return &CA{cert: cert, key: key, cache: newCertCache(certCacheSize)}, nil
}

// CertForHost returns a leaf certificate for host, generating and caching one if needed.
func (ca *CA) CertForHost(host string) (*tls.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	if c, ok := ca.cache.get(host); ok {
		return c, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	tlsCert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		return nil, err
	}
	ca.cache.set(host, &tlsCert)
	return &tlsCert, nil
}

func savePEM(path, typ string, data []byte) error {
	// Use 0600 for private keys, 0644 for certificates.
	perm := os.FileMode(0644)
	if typ == "EC PRIVATE KEY" || typ == "RSA PRIVATE KEY" {
		perm = 0600
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: typ, Bytes: data})
}
