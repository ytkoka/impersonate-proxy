package fp

import (
	"fmt"
	"net"
	"strings"

	utls "github.com/refraction-networking/utls"

	"impersonate-proxy/config"
)

var presets = map[string]utls.ClientHelloID{
	"chrome":  utls.HelloChrome_Auto,
	"firefox": utls.HelloFirefox_Auto,
	"safari":  utls.HelloSafari_Auto,
	"edge":    utls.HelloEdge_Auto,
	"ios":     utls.HelloIOS_Auto,
	"random":  utls.HelloRandomized,
	"golang":  utls.HelloGolang,
}

func PresetNames() string {
	names := make([]string, 0, len(presets)+1)
	for k := range presets {
		names = append(names, k)
	}
	names = append(names, "custom")
	return strings.Join(names, ", ")
}

// Conn wraps a net.Conn with the ALPN protocol negotiated during the TLS handshake.
type Conn struct {
	net.Conn
	Proto string // "h2" or "http/1.1"
}

type Dialer struct {
	helloID utls.ClientHelloID
	spec    *utls.ClientHelloSpec // non-nil only for preset=="custom"
	preset  string
}

// NewDialer creates a Dialer for a named preset. Used by the management API
// for runtime preset changes; does not support "custom".
func NewDialer(preset string) (*Dialer, error) {
	id, ok := presets[preset]
	if !ok {
		return nil, fmt.Errorf("unknown preset %q (available: %s)", preset, PresetNames())
	}
	return &Dialer{helloID: id, preset: preset}, nil
}

// NewDialerFromConfig creates a Dialer from a TLSConfig, supporting both named
// presets and preset=="custom" with a full custom_hello specification.
func NewDialerFromConfig(cfg config.TLSConfig) (*Dialer, error) {
	if cfg.Preset == "custom" {
		spec, err := buildSpec(cfg.CustomHello)
		if err != nil {
			return nil, fmt.Errorf("build custom TLS spec: %w", err)
		}
		return &Dialer{helloID: utls.HelloCustom, spec: &spec, preset: "custom"}, nil
	}
	return NewDialer(cfg.Preset)
}

// Dial opens a TCP connection to addr, performs a uTLS handshake as host,
// and returns the connection together with the negotiated ALPN protocol.
func (d *Dialer) Dial(host, addr string) (*Conn, error) {
	rawConn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	uconn := utls.UClient(rawConn, &utls.Config{ServerName: host}, d.helloID)
	if d.spec != nil {
		if err := uconn.ApplyPreset(d.spec); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("apply custom TLS spec for %s: %w", host, err)
		}
	}
	if err := uconn.Handshake(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("TLS handshake with %s: %w", host, err)
	}
	proto := uconn.ConnectionState().NegotiatedProtocol
	if proto == "" {
		proto = "http/1.1"
	}
	return &Conn{Conn: uconn, Proto: proto}, nil
}

// ── Custom ClientHello builder ───────────────────────────────────────────────

// defaultSigAlgs mirrors the signature algorithms a typical Chrome client sends.
var defaultSigAlgs = []utls.SignatureScheme{
	utls.ECDSAWithP256AndSHA256,
	utls.PSSWithSHA256,
	utls.PKCS1WithSHA256,
	utls.ECDSAWithP384AndSHA384,
	utls.PSSWithSHA384,
	utls.PKCS1WithSHA384,
	utls.PSSWithSHA512,
	utls.PKCS1WithSHA512,
}

func buildSpec(cfg config.CustomHello) (utls.ClientHelloSpec, error) {
	if len(cfg.CipherSuites) == 0 {
		return utls.ClientHelloSpec{}, fmt.Errorf("custom_hello.cipher_suites must not be empty")
	}
	if len(cfg.Extensions) == 0 {
		return utls.ClientHelloSpec{}, fmt.Errorf("custom_hello.extensions must not be empty")
	}

	curves, err := parseCurves(cfg.Curves)
	if err != nil {
		return utls.ClientHelloSpec{}, err
	}
	versions, err := parseTLSVersions(cfg.Versions)
	if err != nil {
		return utls.ClientHelloSpec{}, err
	}

	exts := make([]utls.TLSExtension, 0, len(cfg.Extensions))
	for _, id := range cfg.Extensions {
		exts = append(exts, buildExtension(id, curves, versions))
	}

	return utls.ClientHelloSpec{
		TLSVersMin:         minUint16(versions),
		TLSVersMax:         maxUint16(versions),
		CipherSuites:       cfg.CipherSuites,
		CompressionMethods: []byte{0}, // no compression
		Extensions:         exts,
	}, nil
}

// buildExtension maps an extension type ID to the corresponding uTLS struct.
// Values matching the GREASE pattern (0xXAXA) become UtlsGREASEExtension.
// Unknown IDs fall back to GenericExtension with no payload.
func buildExtension(id uint16, curves []utls.CurveID, versions []uint16) utls.TLSExtension {
	if id&0x0F0F == 0x0A0A { // GREASE pattern: 0x0a0a, 0x1a1a, 0x2a2a …
		return &utls.UtlsGREASEExtension{}
	}
	switch id {
	case 0:
		return &utls.SNIExtension{}
	case 5:
		return &utls.StatusRequestExtension{}
	case 10:
		return &utls.SupportedCurvesExtension{Curves: curves}
	case 11:
		return &utls.SupportedPointsExtension{SupportedPoints: []byte{0}}
	case 13:
		return &utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: defaultSigAlgs}
	case 16:
		return &utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}}
	case 18:
		return &utls.SCTExtension{}
	case 21:
		return &utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle}
	case 23:
		return &utls.UtlsExtendedMasterSecretExtension{}
	case 27:
		return &utls.UtlsCompressCertExtension{}
	case 28:
		return &utls.FakeRecordSizeLimitExtension{Limit: 0x4001}
	case 35:
		return &utls.SessionTicketExtension{}
	case 43:
		return &utls.SupportedVersionsExtension{Versions: versions}
	case 45:
		return &utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}}
	case 50:
		return &utls.SignatureAlgorithmsCertExtension{SupportedSignatureAlgorithms: defaultSigAlgs}
	case 51:
		return &utls.KeyShareExtension{KeyShares: keySharesForCurves(curves)}
	case 17513:
		return &utls.ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}}
	case 65281:
		return &utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient}
	default:
		return &utls.GenericExtension{Id: id}
	}
}

// keySharesForCurves picks the first two key-share-capable curves (X25519, P256).
func keySharesForCurves(curves []utls.CurveID) []utls.KeyShare {
	var ks []utls.KeyShare
	for _, c := range curves {
		if c == utls.X25519 || c == utls.CurveP256 {
			ks = append(ks, utls.KeyShare{Group: c})
		}
		if len(ks) == 2 {
			break
		}
	}
	return ks
}

// ── Parsers ──────────────────────────────────────────────────────────────────

func parseCurves(names []string) ([]utls.CurveID, error) {
	ids := make([]utls.CurveID, 0, len(names))
	for _, name := range names {
		if strings.EqualFold(name, "grease") {
			ids = append(ids, utls.CurveID(utls.GREASE_PLACEHOLDER))
			continue
		}
		id, err := parseCurve(name)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func parseCurve(name string) (utls.CurveID, error) {
	switch strings.ToLower(name) {
	case "x25519":
		return utls.X25519, nil
	case "x25519kyber768", "x25519kyber768draft00":
		return utls.X25519Kyber768Draft00, nil
	case "p256", "secp256r1":
		return utls.CurveP256, nil
	case "p384", "secp384r1":
		return utls.CurveP384, nil
	case "p521", "secp521r1":
		return utls.CurveP521, nil
	default:
		return 0, fmt.Errorf("unknown curve %q (use X25519, X25519Kyber768, P256, P384, P521)", name)
	}
}

func parseTLSVersions(vs []string) ([]uint16, error) {
	ids := make([]uint16, 0, len(vs))
	for _, v := range vs {
		id, err := parseTLSVersion(v)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func parseTLSVersion(v string) (uint16, error) {
	switch v {
	case "1.0":
		return utls.VersionTLS10, nil
	case "1.1":
		return utls.VersionTLS11, nil
	case "1.2":
		return utls.VersionTLS12, nil
	case "1.3":
		return utls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unknown TLS version %q (use 1.0, 1.1, 1.2, or 1.3)", v)
	}
}

func minUint16(vals []uint16) uint16 {
	if len(vals) == 0 {
		return utls.VersionTLS12
	}
	m := vals[0]
	for _, v := range vals[1:] {
		if v < m {
			m = v
		}
	}
	return m
}

func maxUint16(vals []uint16) uint16 {
	if len(vals) == 0 {
		return utls.VersionTLS13
	}
	m := vals[0]
	for _, v := range vals[1:] {
		if v > m {
			m = v
		}
	}
	return m
}
