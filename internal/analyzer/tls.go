package analyzer

import (
    "crypto/tls"
    "fmt"
    "net/http"
    "strings"
    "time"

    "github.com/zharfatech/http-header-analyzer/internal/models"
)

// analyzeTLS extracts TLS information from the HTTP response
func analyzeTLS(resp *http.Response) models.TLSInfo {
    info := models.TLSInfo{
        Valid: true,
    }

    if resp.TLS == nil {
        info.Valid = false
        info.Version = "N/A (HTTP only)"
        return info
    }

    // Determine TLS version
    info.Version = tlsVersion(resp.TLS)

    // Determine cipher suite
    info.CipherSuite = cipherSuiteName(resp.TLS.CipherSuite)

    // Extract certificate info
    if len(resp.TLS.PeerCertificates) > 0 {
        cert := resp.TLS.PeerCertificates[0]
        info.Subject = cert.Subject.CommonName
        info.Issuer = cert.Issuer.CommonName
        info.ExpiresAt = cert.NotAfter.Format(time.RFC3339)

        // Check if certificate is valid
        now := time.Now()
        if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
            info.Valid = false
        }
    }

    return info
}

// tlsVersion converts the TLS version constant to a human-readable string
func tlsVersion(tlsState *tls.ConnectionState) string {
    switch tlsState.Version {
    case tls.VersionTLS10:
        return "TLS 1.0"
    case tls.VersionTLS11:
        return "TLS 1.1"
    case tls.VersionTLS12:
        return "TLS 1.2"
    case tls.VersionTLS13:
        return "TLS 1.3"
    default:
        return fmt.Sprintf("Unknown (0x%04X)", tlsState.Version)
    }
}

// cipherSuiteName returns a human-readable name for the cipher suite
func cipherSuiteName(cipher uint16) string {
    // Check standard cipher suites
    for _, c := range tls.CipherSuites() {
        if c.ID == cipher {
            return c.Name
        }
    }
    
    // Check TLS 1.3 cipher suites if available
    // Note: tls.TLS13CipherSuites() was added in Go 1.14
    // If you are on an older version, this might not be available.
    // We can manually define common TLS 1.3 ciphers if needed.
    tls13Ciphers := []struct {
        ID   uint16
        Name string
    }{
        {0x1301, "TLS_AES_128_GCM_SHA256"},
        {0x1302, "TLS_AES_256_GCM_SHA384"},
        {0x1303, "TLS_CHACHA20_POLY1305_SHA256"},
        {0x1304, "TLS_AES_128_CCM_SHA256"},
        {0x1305, "TLS_AES_128_CCM_8_SHA256"},
    }

    for _, c := range tls13Ciphers {
        if c.ID == cipher {
            return c.Name
        }
    }

    return fmt.Sprintf("Unknown (0x%04X)", cipher)
}

// isWeakCipher checks if a cipher suite is considered weak
func isWeakCipher(cipherName string) bool {
    weakCiphers := []string{
        "RC4", "DES", "3DES", "NULL", "EXPORT",
        "MD5", "anon",
    }
    for _, weak := range weakCiphers {
        if strings.Contains(strings.ToUpper(cipherName), strings.ToUpper(weak)) {
            return true
        }
    }
    return false
}