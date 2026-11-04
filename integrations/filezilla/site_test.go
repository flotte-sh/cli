package filezilla

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestNewSite(t *testing.T) {
	site, err := NewSite("alice", "server.example.com:2222")
	if err != nil {
		t.Fatal(err)
	}
	if site.Host != "server.example.com" || site.Port != 2222 || site.User != "alice" {
		t.Fatalf("site = %#v", site)
	}
}

func TestNewSiteRejectsInvalidTargets(t *testing.T) {
	for _, address := range []string{"", "server.example.com:0", "server.example.com:65536", "[bad-v6]:22"} {
		t.Run(address, func(t *testing.T) {
			if _, err := NewSite("alice", address); err == nil {
				t.Fatalf("accepted target %q", address)
			}
		})
	}
}

func TestSiteManagerXMLProfile(t *testing.T) {
	content, err := siteManagerXML(Site{Host: "server.example.com", Port: 22, User: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	var profile struct {
		Servers struct {
			Folder struct {
				Name   string `xml:",chardata"`
				Server struct {
					Host      string `xml:"Host"`
					Port      int    `xml:"Port"`
					Protocol  int    `xml:"Protocol"`
					LogonType int    `xml:"Logontype"`
					User      string `xml:"User"`
					Name      string `xml:"Name"`
					Parameter struct {
						Name  string `xml:"Name,attr"`
						Value string `xml:",chardata"`
					} `xml:"Parameter"`
				} `xml:"Server"`
			} `xml:"Folder"`
		} `xml:"Servers"`
	}
	if err := xml.Unmarshal([]byte(content), &profile); err != nil {
		t.Fatalf("invalid FileZilla Site Manager XML: %v", err)
	}
	site := profile.Servers.Folder.Server
	if strings.TrimSpace(profile.Servers.Folder.Name) != "Flotte" || site.Name != "session" || site.Host != "server.example.com" || site.Port != 22 || site.Protocol != 1 || site.LogonType != 1 || site.User != "alice" || site.Parameter.Name != unknownAgentKeyOption || site.Parameter.Value != "1" {
		t.Fatalf("unexpected FileZilla site profile: %#v", profile)
	}
}

func TestHostkeyStoreXMLPinsApprovedKeys(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	key, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	content, err := hostkeyStoreXML(Site{Host: "Server.Example.com", Port: 22, User: "alice"}, []ssh.PublicKey{key})
	if err != nil {
		t.Fatal(err)
	}
	var store struct {
		Servers []struct {
			Host     string   `xml:"Host,attr"`
			Port     int      `xml:"Port,attr"`
			Hostkeys []string `xml:"Hostkey"`
		} `xml:"Server"`
	}
	if err := xml.Unmarshal([]byte(content), &store); err != nil {
		t.Fatalf("invalid FileZilla hostkey store XML: %v", err)
	}
	if len(store.Servers) != 1 || store.Servers[0].Host != "server.example.com" || store.Servers[0].Port != 22 || len(store.Servers[0].Hostkeys) != 1 {
		t.Fatalf("unexpected FileZilla hostkey store: %#v", store)
	}
	if got := store.Servers[0].Hostkeys[0]; got != base64.StdEncoding.EncodeToString(key.Marshal()) {
		t.Fatalf("hostkey = %q, want encoded approved public key", got)
	}
}

func TestCreateSessionConfigUsesTemporaryDirectories(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	key, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	config, err := createSessionConfig(Site{Host: "server.example.com", Port: 22, User: "alice"}, []ssh.PublicKey{key})
	if err != nil {
		t.Fatal(err)
	}
	defer config.cleanup()
	for _, path := range []string{
		config.configDir + "/sitemanager.xml",
		config.configDir + "/hostkeys.xml",
		config.dataDir + "/fzdefaults.xml",
		config.configDir + "/fzdefaults.xml",
	} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("missing isolated FileZilla config %s: %v", path, err)
		}
	}
	defaults, err := os.ReadFile(config.configDir + "/fzdefaults.xml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(defaults), `name="Kiosk mode">2`) {
		t.Fatalf("temporary FileZilla profile does not disable settings writes: %s", defaults)
	}
}

func TestSupportsCertificateAgentVersion(t *testing.T) {
	for _, test := range []struct {
		output string
		want   bool
	}{
		{output: "FileZilla 3.70.6", want: false},
		{output: "FileZilla 3.71.0", want: true},
		{output: "FileZilla Pro 3.71.1 (x86_64)", want: true},
		{output: "FileZilla 4.0.0", want: true},
		{output: "unknown", want: false},
	} {
		if got := supportsCertificateAgent(test.output); got != test.want {
			t.Errorf("supportsCertificateAgent(%q) = %t, want %t", test.output, got, test.want)
		}
	}
}

func TestValidateVersionOutputAcceptsValidVersionDespiteExitError(t *testing.T) {
	err := validateVersionOutput([]byte("FileZilla 3.71.1 official build, compiled on 2026-08-26\n"), errors.New("exit status 0xffffffff"))
	if err != nil {
		t.Fatalf("valid version output was rejected: %v", err)
	}
}
