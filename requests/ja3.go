package requests

// ja3.go implements JA3 fingerprint string parsing into a utls ClientHelloSpec.
//
// JA3 format: TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
// Example:    771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0
//
// Reference: https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967/

import (
	"fmt"
	"strconv"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// parseUint16s splits a dash-separated string of numbers into []uint16.
func parseUint16s(s string) ([]uint16, error) {
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, "-")
	out := make([]uint16, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.ParseUint(strings.TrimSpace(p), 10, 16)
		if err != nil {
			return nil, fmt.Errorf("parse uint16 %q: %w", p, err)
		}
		out = append(out, uint16(n))
	}
	return out, nil
}

// BuildSpecFromJA3 parses a JA3 fingerprint string and returns a utls ClientHelloSpec
// that produces a matching TLS ClientHello.
//
// Note: JA3 does not encode all parameters (e.g. signature algorithms, key shares
// are inferred from known browser defaults). The resulting fingerprint will match
// the JA3 hash exactly.
func BuildSpecFromJA3(ja3 string) (*utls.ClientHelloSpec, error) {
	parts := strings.Split(ja3, ",")
	if len(parts) != 5 {
		return nil, fmt.Errorf("JA3: expected 5 comma-separated fields, got %d", len(parts))
	}

	// Field 1: TLS version (wire format: 0x0303 = 771 = TLS 1.2)
	tlsVerInt, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 16)
	if err != nil {
		return nil, fmt.Errorf("JA3 TLS version: %w", err)
	}
	tlsVer := uint16(tlsVerInt)
	curlTLSMin, curlTLSMax := ja3TLSRange(tlsVer)

	// Field 2: Cipher suites
	ciphers, err := parseUint16s(parts[1])
	if err != nil {
		return nil, fmt.Errorf("JA3 ciphers: %w", err)
	}
	// Always include GREASE cipher at the beginning (Chrome does this)
	// We omit GREASE here since it's added via UtlsGREASEExtension if present.

	// Field 3: Extension IDs in order
	extIDs, err := parseUint16s(parts[2])
	if err != nil {
		return nil, fmt.Errorf("JA3 extensions: %w", err)
	}

	// Field 4: Elliptic curves (named groups)
	curveIDs, err := parseUint16s(parts[3])
	if err != nil {
		return nil, fmt.Errorf("JA3 curves: %w", err)
	}
	curves := make([]utls.CurveID, len(curveIDs))
	for i, id := range curveIDs {
		curves[i] = utls.CurveID(id)
	}

	// Field 5: EC point formats (usually just 0 = uncompressed)
	pointFormats, err := parseUint16s(parts[4])
	if err != nil {
		return nil, fmt.Errorf("JA3 point formats: %w", err)
	}
	pointFmtBytes := make([]uint8, len(pointFormats))
	for i, v := range pointFormats {
		pointFmtBytes[i] = uint8(v)
	}

	// Build the extension list in the exact order from the JA3 string.
	extensions := make([]utls.TLSExtension, 0, len(extIDs))
	for _, id := range extIDs {
		ext, err := ja3ExtensionFor(id, curves, pointFmtBytes, curlTLSMax)
		if err != nil {
			// Unknown extension — use generic passthrough
			extensions = append(extensions, &utls.GenericExtension{Id: id})
			continue
		}
		extensions = append(extensions, ext)
	}

	spec := &utls.ClientHelloSpec{
		TLSVersMin:         curlTLSMin,
		TLSVersMax:         curlTLSMax,
		CipherSuites:       ciphers,
		CompressionMethods: []uint8{0}, // no compression
		Extensions:         extensions,
	}
	return spec, nil
}

// ja3TLSRange maps a JA3 TLS wire version to utls min/max version constants.
func ja3TLSRange(wireVer uint16) (min, max uint16) {
	switch wireVer {
	case 0x0301: // TLS 1.0
		return utls.VersionTLS10, utls.VersionTLS13
	case 0x0302: // TLS 1.1
		return utls.VersionTLS11, utls.VersionTLS13
	case 0x0303: // TLS 1.2 — most common
		return utls.VersionTLS12, utls.VersionTLS13
	case 0x0304: // TLS 1.3
		return utls.VersionTLS13, utls.VersionTLS13
	default:
		return utls.VersionTLS12, utls.VersionTLS13
	}
}

// ja3ExtensionFor maps a TLS extension ID to the corresponding utls TLSExtension.
// curves and pointFmts come from JA3 fields 4 and 5.
func ja3ExtensionFor(id uint16, curves []utls.CurveID, pointFmts []uint8, tlsMaxVer uint16) (utls.TLSExtension, error) {
	switch id {
	case 0: // server_name (SNI)
		return &utls.SNIExtension{}, nil

	case 5: // status_request (OCSP)
		return &utls.StatusRequestExtension{}, nil

	case 10: // supported_groups (elliptic curves)
		return &utls.SupportedCurvesExtension{Curves: curves}, nil

	case 11: // ec_point_formats
		return &utls.SupportedPointsExtension{SupportedPoints: pointFmts}, nil

	case 13: // signature_algorithms
		return &utls.SignatureAlgorithmsExtension{
			SupportedSignatureAlgorithms: defaultSigAlgs(),
		}, nil

	case 16: // ALPN
		return &utls.ALPNExtension{
			AlpnProtocols: []string{"h2", "http/1.1"},
		}, nil

	case 17: // status_request_v2
		return &utls.StatusRequestV2Extension{}, nil

	case 18: // signed_certificate_timestamp (SCT)
		return &utls.SCTExtension{}, nil

	case 21: // padding
		return &utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle}, nil

	case 22: // encrypt_then_mac
		return &utls.GenericExtension{Id: 22}, nil

	case 23: // extended_master_secret
		return &utls.ExtendedMasterSecretExtension{}, nil

	case 27: // compress_certificate
		return &utls.UtlsCompressCertExtension{
			Algorithms: []utls.CertCompressionAlgo{utls.CertCompressionBrotli},
		}, nil

	case 28: // record_size_limit
		return &utls.FakeRecordSizeLimitExtension{Limit: 0x4001}, nil

	case 34: // delegated_credentials
		return &utls.FakeDelegatedCredentialsExtension{
			SupportedSignatureAlgorithms: defaultSigAlgs(),
		}, nil

	case 35: // session_ticket
		return &utls.SessionTicketExtension{}, nil

	case 43: // supported_versions
		versions := []uint16{utls.VersionTLS13, utls.VersionTLS12}
		if tlsMaxVer == utls.VersionTLS12 {
			versions = []uint16{utls.VersionTLS12}
		}
		return &utls.SupportedVersionsExtension{Versions: versions}, nil

	case 45: // psk_key_exchange_modes
		return &utls.PSKKeyExchangeModesExtension{
			Modes: []uint8{utls.PskModeDHE},
		}, nil

	case 50: // signature_algorithms_cert
		return &utls.SignatureAlgorithmsCertExtension{
			SupportedSignatureAlgorithms: defaultSigAlgs(),
		}, nil

	case 51: // key_share
		return &utls.KeyShareExtension{
			KeyShares: defaultKeyShares(curves),
		}, nil

	case 17513: // application_settings (ALPS, BoringSSL)
		return &utls.ApplicationSettingsExtension{
			SupportedProtocols: []string{"h2"},
		}, nil

	case 17613: // application_settings new codepoint
		return &utls.ApplicationSettingsExtensionNew{
			SupportedProtocols: []string{"h2"},
		}, nil

	case 65281: // renegotiation_info
		return &utls.RenegotiationInfoExtension{
			Renegotiation: utls.RenegotiateOnceAsClient,
		}, nil

	default:
		// For GREASE values (0x?a?a pattern) use the GREASE extension
		if isGREASE(id) {
			return &utls.UtlsGREASEExtension{}, nil
		}
		return nil, fmt.Errorf("unknown extension %d", id)
	}
}

// isGREASE returns true if id is a GREASE value (RFC 8701).
// GREASE values have identical high and low bytes, each with low nibble 0xa:
// 0x0a0a, 0x1a1a, 0x2a2a, …, 0xfafa.
func isGREASE(id uint16) bool {
	return id&0x0f == 0x0a && (id>>8) == (id&0xff)
}

// defaultSigAlgs returns the signature algorithms list used by Chrome.
func defaultSigAlgs() []utls.SignatureScheme {
	return []utls.SignatureScheme{
		utls.ECDSAWithP256AndSHA256,
		utls.PSSWithSHA256,
		utls.PKCS1WithSHA256,
		utls.ECDSAWithP384AndSHA384,
		utls.PSSWithSHA384,
		utls.PKCS1WithSHA384,
		utls.PSSWithSHA512,
		utls.PKCS1WithSHA512,
	}
}

// defaultKeyShares returns key shares to include based on the curve list.
// We include X25519 and P-256 by default (Chrome does this).
func defaultKeyShares(curves []utls.CurveID) []utls.KeyShare {
	shares := make([]utls.KeyShare, 0, 2)
	for _, curve := range curves {
		switch curve {
		case utls.X25519:
			shares = append(shares, utls.KeyShare{Group: utls.X25519})
		case utls.CurveP256:
			shares = append(shares, utls.KeyShare{Group: utls.CurveP256})
		}
		if len(shares) >= 2 {
			break
		}
	}
	if len(shares) == 0 {
		shares = []utls.KeyShare{{Group: utls.X25519}}
	}
	return shares
}
