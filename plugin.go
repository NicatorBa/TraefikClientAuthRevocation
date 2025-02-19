package clientauthrevocation

import (
	"context"
	"crypto/x509"
	"io"
	"net/http"
)

type Config struct{}

func CreateConfig() *Config {
	return &Config{}
}

type ClientAuthRevocation struct {
	next http.Handler
	name string
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	car := &ClientAuthRevocation{
		next: next,
		name: name,
	}

	return car, nil
}

func (car *ClientAuthRevocation) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "Client certificate is required for authentication.", http.StatusUnauthorized)
		return
	}

	clientCert := r.TLS.PeerCertificates[0]

	var rl *x509.RevocationList
	for _, url := range clientCert.CRLDistributionPoints {
		resp, err := http.Get(url)
		if err != nil {
			continue
		}

		defer resp.Body.Close()

		der, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		rl, err = x509.ParseRevocationList(der)
		if err != nil {
			continue
		}

		break
	}

	if rl == nil {
		car.next.ServeHTTP(w, r)

		return
	}

	for _, rce := range rl.RevokedCertificateEntries {
		if rce.SerialNumber.Cmp(clientCert.SerialNumber) != 0 {
			continue
		}

		http.Error(w, "Client certificate is revoked.", http.StatusUnauthorized)
		return
	}

	car.next.ServeHTTP(w, r)
}
