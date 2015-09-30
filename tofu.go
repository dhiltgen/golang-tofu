package tofu

import (
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
)

type CertDetail struct {
	Subject     string
	Issuer      string
	Fingerprint string
}

var (
	ErrNoMatchingFingerprint = errors.New("Server certificate(s) didn't match trusted fingerprint.")
	ErrCertExpired           = errors.New("Server certificate has expired.")
	ErrCertNotYetValid       = errors.New("Server certificate is not yet valid.")
	ErrMalformedCert         = errors.New("Malformed certificate")
	ErrNoCertsDetected       = errors.New("No server certificates detected")
)

// Connect to an untrusted server, and get cert information about it
func GetFingerprints(addr string) ([]CertDetail, error) {
	ret := []CertDetail{}

	// If the port isn't specified, assume https standard port
	if !strings.Contains(addr, ":") {
		addr = addr + ":443"
	}
	log.Debugf("Performing TOFU check on %s", addr)

	config := &tls.Config{
		InsecureSkipVerify: true, // By definition, we're trying to build the trust...
	}
	conn, err := tls.Dial("tcp", addr, config)
	if err != nil {
		log.Infof("Unable to connect to %s: %s", addr, err)
		return nil, err
	} else {
		state := conn.ConnectionState()

		for _, cert := range state.PeerCertificates {
			ret = append(ret, CertDetail{
				Subject:     fmt.Sprintf("Subject: %s", cert.Subject.CommonName),
				Issuer:      fmt.Sprintf("Issuer: %s", cert.Issuer.CommonName),
				Fingerprint: getFingerprint(cert.Raw),
			})
		}
		if len(ret) == 0 {
			return nil, ErrNoCertsDetected
		}
		return ret, nil
	}
}

// Given a trusted fingerprint, return an http client that will verify a match
func GetTofuClient(fingerprint string) (*http.Client, error) {
	log.Debugf("Attempting connection with trusted fingerprint: %s", fingerprint)
	dial := func(network, addr string) (net.Conn, error) {
		config := &tls.Config{
			InsecureSkipVerify: true, // We'll verify ourselves
		}

		conn, err := tls.Dial(network, addr, config)
		if err != nil {
			log.Infof("Unable to connect to %s: %s", addr, err)
			return nil, err

		}
		state := conn.ConnectionState()
		now := time.Now()
		matched := false
		for _, cert := range state.PeerCertificates {
			if fingerprint == getFingerprint(cert.Raw) {
				matched = true
			}
			if now.Before(cert.NotBefore) {
				conn.Close()
				return nil, ErrCertNotYetValid
			}
			if now.After(cert.NotAfter) {
				conn.Close()
				return nil, ErrCertExpired
			}
		}
		if !matched {
			conn.Close()
			return nil, ErrNoMatchingFingerprint
		}
		// If we've gotten this far, then we can trust the server
		log.Debug("Server cert(s) passed TOFU tests")
		return conn, nil
	}
	return &http.Client{
		Transport: &http.Transport{
			DialTLS: dial,
		},
	}, nil
}

func getFingerprint(der []byte) string {
	hash := sha1.Sum(der)
	hexified := make([][]byte, len(hash))
	for i, data := range hash {
		hexified[i] = []byte(fmt.Sprintf("%02X", data))
	}
	return fmt.Sprintf("SHA1 Fingerprint=%s", string(bytes.Join(hexified, []byte(":"))))
}
