package analyzer

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/ItsWanheda/http-header-analyzer/internal/models"
)

func analyzeCertificate(targetURL string, cert *x509.Certificate) models.CertificateInfo {
	info := models.CertificateInfo{
		Present: true,
	}

	if cert == nil {
		info.Present = false
		info.Valid = false
		return info
	}

	now := time.Now()

	info.Subject = cert.Subject.CommonName
	info.Issuer = cert.Issuer.CommonName
	info.SerialNumber = cert.SerialNumber.String()
	info.NotBefore = cert.NotBefore.Format(time.RFC3339)
	info.NotAfter = cert.NotAfter.Format(time.RFC3339)
	info.Signature = cert.SignatureAlgorithm.String()
	info.PublicKey = cert.PublicKeyAlgorithm.String()
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		info.KeyStrengthBits = key.N.BitLen()
		info.PublicKey = fmt.Sprintf("RSA (%d-bit)", info.KeyStrengthBits)
		info.WeakPublicKey = info.KeyStrengthBits < 2048
	case *ecdsa.PublicKey:
		info.KeyStrengthBits = key.Curve.Params().BitSize
		info.PublicKey = fmt.Sprintf("ECDSA (%d-bit)", info.KeyStrengthBits)
		info.WeakPublicKey = info.KeyStrengthBits < 256
	case ed25519.PublicKey:
		info.KeyStrengthBits = 256
		info.PublicKey = "Ed25519"
	default:
		info.WeakPublicKey = true
	}
	switch cert.SignatureAlgorithm {
	case x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		info.WeakSignature = true
	}
	info.DNSNames = append([]string{}, cert.DNSNames...)

	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		info.Valid = false
	} else {
		info.Valid = true
	}

	info.DaysRemaining = int(time.Until(cert.NotAfter).Hours() / 24)

	for _, name := range cert.DNSNames {
		if strings.HasPrefix(name, "*.") {
			info.Wildcard = true
			break
		}
	}

	info.MatchesTarget = certificateMatchesTarget(targetURL, cert)
	// The HTTPS request has already succeeded with Go's default certificate-chain
	// and hostname verification. Keep key/signature strength as separate findings.
	info.Valid = info.Valid && info.MatchesTarget

	return info
}

func certificateMatchesTarget(targetURL string, cert *x509.Certificate) bool {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return false
	}

	host := parsed.Hostname()

	if host == "" {
		return false
	}

	if ip := net.ParseIP(host); ip != nil {
		for _, candidate := range cert.IPAddresses {
			if candidate.Equal(ip) {
				return true
			}
		}

		return false
	}

	return cert.VerifyHostname(host) == nil
}

func certificateSummary(cert models.CertificateInfo) string {
	if !cert.Present {
		return "No TLS certificate available"
	}

	if !cert.Valid {
		return "Certificate is expired or not yet valid"
	}

	if !cert.MatchesTarget {
		return "Certificate does not match the target hostname"
	}

	if cert.DaysRemaining <= 30 {
		return fmt.Sprintf(
			"Certificate expires in %d days",
			cert.DaysRemaining,
		)
	}

	return "Certificate is valid"
}