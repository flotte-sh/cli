package winscp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/flotte-sh/flotte-cli/integrations/internal/certagent"
	"golang.org/x/crypto/ssh"
)

func winSCPTestSigner(t *testing.T, seed byte) ssh.Signer {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func winSCPTestAuthorizedKey(key ssh.PublicKey) string {
	return string(ssh.MarshalAuthorizedKey(key))
}

func winSCPTestFingerprint(key ssh.PublicKey, bits int) string {
	digest := sha256.Sum256(key.Marshal())
	return fmt.Sprintf("%s %d %s", key.Type(), bits, base64.RawStdEncoding.EncodeToString(digest[:]))
}

func winSCPTestCertificate(t *testing.T, key ssh.PublicKey, certType uint32, principals []string, validAfter, validBefore time.Time) *ssh.Certificate {
	t.Helper()
	cert := &ssh.Certificate{
		Key:             key,
		CertType:        certType,
		ValidPrincipals: principals,
		ValidAfter:      uint64(validAfter.Unix()),
		ValidBefore:     uint64(validBefore.Unix()),
	}
	if err := cert.SignCert(rand.Reader, winSCPTestSigner(t, 99)); err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestWinSCPHostFingerprintsApprovedKeys(t *testing.T) {
	presented := winSCPTestSigner(t, 1).PublicKey()
	rsaPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := ssh.NewPublicKey(&rsaPrivate.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaKey, err := ssh.NewPublicKey(&ecdsaPrivate.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	approved := []string{
		winSCPTestAuthorizedKey(presented),
		winSCPTestAuthorizedKey(rsaKey),
		winSCPTestAuthorizedKey(ecdsaKey),
	}
	want := make(map[string]bool, len(approved))
	for _, fingerprint := range []string{
		winSCPTestFingerprint(presented, 255),
		winSCPTestFingerprint(rsaKey, rsaPrivate.N.BitLen()),
		winSCPTestFingerprint(ecdsaKey, elliptic.P256().Params().BitSize),
	} {
		want[fingerprint] = true
	}
	for _, key := range []ssh.PublicKey{presented, rsaKey, ecdsaKey} {
		t.Run(key.Type(), func(t *testing.T) {
			got, err := certagent.WinSCPHostFingerprints(winSCPTestAuthorizedKey(key), approved)
			if err != nil {
				t.Fatal(err)
			}
			parts := strings.Split(got, ";")
			if len(parts) != len(want) {
				t.Fatalf("fingerprints = %q, want exactly %d approved fingerprints", got, len(want))
			}
			seen := make(map[string]bool, len(parts))
			for _, part := range parts {
				if !want[part] || seen[part] {
					t.Errorf("unexpected or repeated fingerprint %q in %q", part, got)
				}
				seen[part] = true
			}
		})
	}
}

func TestWinSCPHostFingerprintsRejectUnsafeKeys(t *testing.T) {
	key := winSCPTestSigner(t, 2).PublicKey()
	other := winSCPTestSigner(t, 3).PublicKey()
	keyText := winSCPTestAuthorizedKey(key)
	otherText := winSCPTestAuthorizedKey(other)
	now := time.Unix(1_800_000_000, 0).UTC()
	hostCert := winSCPTestAuthorizedKey(winSCPTestCertificate(t, key, ssh.HostCert, []string{"host.example"}, now.Add(-time.Hour), now.Add(time.Hour)))
	cases := []struct {
		name      string
		presented string
		approved  []string
	}{
		{"unapproved presented key", otherText, []string{keyText}},
		{"empty approved list", keyText, nil},
		{"empty approved key", keyText, []string{keyText, ""}},
		{"malformed approved key", keyText, []string{keyText, "not an SSH key"}},
		{"empty presented key", "", []string{keyText}},
		{"malformed presented key", "not an SSH key", []string{keyText}},
		{"extra presented key", keyText + otherText, []string{keyText, otherText}},
		{"extra approved key", keyText, []string{keyText + otherText}},
		{"presented trailing garbage", keyText + "garbage", []string{keyText}},
		{"approved trailing garbage", keyText, []string{keyText, otherText + "garbage"}},
		{"presented host certificate", hostCert, []string{hostCert}},
		{"approved host certificate", keyText, []string{keyText, hostCert}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := certagent.WinSCPHostFingerprints(tc.presented, tc.approved); err == nil {
				t.Fatalf("accepted unsafe host pinning input: %q", got)
			}
		})
	}
}

func TestValidateWinSCPCertificate(t *testing.T) {
	now := time.Now().UTC()
	key := winSCPTestSigner(t, 4).PublicKey()
	other := winSCPTestSigner(t, 5).PublicKey()
	valid := winSCPTestCertificate(t, key, ssh.UserCert, []string{"other-user", "alice"}, now.Add(-time.Hour), now.Add(time.Hour))
	validText := winSCPTestAuthorizedKey(valid)
	got, err := certagent.ValidateCertificate(validText, key, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || !bytes.Equal(got.Marshal(), valid.Marshal()) {
		t.Fatal("validation did not return the supplied certificate")
	}
	cases := []struct {
		name string
		text string
		key  ssh.PublicKey
		user string
	}{
		{"wrong generated key", validText, other, "alice"},
		{"wrong principal", validText, key, "mallory"},
		{"no principals", winSCPTestAuthorizedKey(winSCPTestCertificate(t, key, ssh.UserCert, nil, now.Add(-time.Hour), now.Add(time.Hour))), key, "alice"},
		{"host certificate", winSCPTestAuthorizedKey(winSCPTestCertificate(t, key, ssh.HostCert, []string{"alice"}, now.Add(-time.Hour), now.Add(time.Hour))), key, "alice"},
		{"expired certificate", winSCPTestAuthorizedKey(winSCPTestCertificate(t, key, ssh.UserCert, []string{"alice"}, now.Add(-time.Hour), now)), key, "alice"},
		{"future certificate", winSCPTestAuthorizedKey(winSCPTestCertificate(t, key, ssh.UserCert, []string{"alice"}, now.Add(time.Minute), now.Add(time.Hour))), key, "alice"},
		{"ordinary public key", winSCPTestAuthorizedKey(key), key, "alice"},
		{"empty certificate", "", key, "alice"},
		{"malformed certificate", "not an SSH certificate", key, "alice"},
		{"multiple certificates", validText + validText, key, "alice"},
		{"trailing public key", validText + winSCPTestAuthorizedKey(other), key, "alice"},
		{"trailing garbage", validText + "garbage", key, "alice"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if cert, err := certagent.ValidateCertificate(tc.text, tc.key, tc.user); err == nil {
				t.Fatalf("accepted invalid certificate: %v", cert)
			}
		})
	}
}

func TestWinSCPSessionURLEscapesUsername(t *testing.T) {
	user := "alice@example:team/password?#% space"
	for _, address := range []string{"host.example:2222", "[2001:db8::1]:65535"} {
		t.Run(address, func(t *testing.T) {
			text, err := winSCPSessionURL(user, address)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := url.Parse(text)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.User == nil || parsed.User.Username() != user {
				t.Fatalf("URL did not preserve username: %q", text)
			}
			if _, hasPassword := parsed.User.Password(); hasPassword {
				t.Fatalf("username became a URL password: %q", text)
			}
			if parsed.Host != address || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
				t.Fatalf("username escaped its URL component: %q", text)
			}
		})
	}
}

func TestWinSCPSessionURLRejectsMalformedTargets(t *testing.T) {
	cases := []struct {
		name    string
		user    string
		address string
	}{
		{"empty user", "", "host.example:22"},
		{"empty host", "alice", ":22"},
		{"missing port", "alice", "host.example"},
		{"empty port", "alice", "host.example:"},
		{"nonnumeric port", "alice", "host.example:ssh"},
		{"zero port", "alice", "host.example:0"},
		{"negative port", "alice", "host.example:-1"},
		{"overflow port", "alice", "host.example:65536"},
		{"signed port", "alice", "host.example:+22"},
		{"unbracketed IPv6", "alice", "2001:db8::1:22"},
		{"host space", "alice", "host name:22"},
		{"host newline", "alice", "host\nname:22"},
		{"host control", "alice", "host\x00name:22"},
		{"host URL userinfo", "alice", "host@evil:22"},
		{"host URL path", "alice", "host/path:22"},
		{"host URL query", "alice", "host?query:22"},
		{"host URL fragment", "alice", "host#fragment:22"},
		{"host URL escape", "alice", "host%2fname:22"},
		{"host backslash", "alice", "host\\name:22"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := winSCPSessionURL(tc.user, tc.address); err == nil {
				t.Fatalf("accepted malformed target: %q", got)
			}
		})
	}
}
