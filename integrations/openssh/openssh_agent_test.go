package openssh

import (
	"crypto/rand"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestCredentialAgentUsesPersistentKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	private, err := LoadCLIPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &ssh.Certificate{Key: signer.PublicKey(), CertType: ssh.UserCert, ValidPrincipals: []string{"alice"}, ValidBefore: ssh.CertTimeInfinity}
	if err := certificate.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}
	_, keyring, err := agentFromCredential(Credential{Certificate: string(ssh.MarshalAuthorizedKey(certificate))})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("persistent key signing")
	signature, err := keyring.Sign(certificate, payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := certificate.Verify(payload, signature); err != nil {
		t.Fatal(err)
	}
	otherHome := t.TempDir()
	t.Setenv("HOME", otherHome)
	t.Setenv("USERPROFILE", otherHome)
	if _, _, err := agentFromCredential(Credential{Certificate: string(ssh.MarshalAuthorizedKey(certificate))}); err == nil {
		t.Fatal("accepted certificate for a different persistent key")
	}
}

func TestAgentLifetimeTracksCertificateValidity(t *testing.T) {
	for _, test := range []struct {
		name        string
		validBefore time.Duration
		want        time.Duration
		tolerance   time.Duration
	}{
		{name: "one hour certificate", validBefore: time.Hour, want: time.Hour, tolerance: 5 * time.Second},
		{name: "ten minute certificate", validBefore: 10 * time.Minute, want: 10 * time.Minute, tolerance: 5 * time.Second},
		{name: "short certificate keeps floor", validBefore: 30 * time.Second, want: 120 * time.Second},
		{name: "infinite certificate keeps floor", validBefore: -1, want: 120 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			private, err := LoadCLIPrivateKey()
			if err != nil {
				t.Fatal(err)
			}
			signer, err := ssh.NewSignerFromKey(private)
			if err != nil {
				t.Fatal(err)
			}
			certificate := &ssh.Certificate{Key: signer.PublicKey(), CertType: ssh.UserCert, ValidPrincipals: []string{"alice"}}
			if test.validBefore < 0 {
				certificate.ValidBefore = ssh.CertTimeInfinity
			} else {
				certificate.ValidBefore = uint64(time.Now().Add(test.validBefore).Unix())
			}
			if err := certificate.SignCert(rand.Reader, signer); err != nil {
				t.Fatal(err)
			}
			lifetime, _, err := agentFromCredential(Credential{Certificate: string(ssh.MarshalAuthorizedKey(certificate))})
			if err != nil {
				t.Fatal(err)
			}
			diff := lifetime - test.want
			if diff < -test.tolerance || diff > test.tolerance {
				t.Fatalf("lifetime = %v, want %v within %v", lifetime, test.want, test.tolerance)
			}
		})
	}
}
