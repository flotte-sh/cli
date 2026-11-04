package winscp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/flotte-sh/flotte-cli/internal/client"
	"golang.org/x/crypto/ssh"
)

func TestCertificateAgentHostKeysRetainApprovedAlgorithms(t *testing.T) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ssh.NewPublicKey(&private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newCertificateAgentFixture(t, t.Context(), nil, nil, func(_ *ssh.Certificate, response *client.SshCertResponse) {
		response.Hostkeys = append(response.Hostkeys, winSCPTestAuthorizedKey(other))
	})
	defer fixture.agent.Close()
	keys, err := fixture.agent.HostKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || !bytes.Equal(keys[1].Marshal(), other.Marshal()) || winSCPTestAuthorizedKey(keys[0]) != fixture.hostkey {
		t.Fatalf("host pins do not contain both approved server identities: %v", keys)
	}
	if _, err := fixture.agent.List(); err != nil {
		t.Fatal(err)
	}
	if fixture.requests.Load() != 1 {
		t.Fatal("preparing host pins did not retain the authorized certificate")
	}
	fixture.agent.Close()
	if keys, err := fixture.agent.HostKeys(); err == nil || len(keys) != 0 {
		t.Fatal("closed agent returned reusable host pins")
	}
}

func TestCertificateAgentHostKeysRejectUnapprovedProbe(t *testing.T) {
	other := winSCPTestSigner(t, 83).PublicKey()
	fixture := newCertificateAgentFixture(t, t.Context(), nil, nil, func(_ *ssh.Certificate, response *client.SshCertResponse) {
		response.Hostkeys = []string{winSCPTestAuthorizedKey(other)}
	})
	defer fixture.agent.Close()
	if keys, err := fixture.agent.HostKeys(); err == nil || len(keys) != 0 {
		t.Fatal("unapproved probe allowed a different server's host pins")
	}
}
