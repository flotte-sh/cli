package filezilla

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

const fileZillaSitePath = "0/Flotte/session"

const unknownAgentKeyOption = "allow_agent_keys_of_unknown_type"

type sessionConfig struct {
	root          string
	dataDir       string
	configDir     string
	xdgConfigHome string
	homeDir       string
}

func createSessionConfig(site Site, hostkeys []ssh.PublicKey) (sessionConfig, error) {
	root, err := os.MkdirTemp("", "flotte-filezilla-")
	if err != nil {
		return sessionConfig{}, fmt.Errorf("create FileZilla session directory: %w", err)
	}
	config := sessionConfig{
		root:          root,
		dataDir:       filepath.Join(root, "data"),
		xdgConfigHome: filepath.Join(root, "xdg"),
		homeDir:       filepath.Join(root, "home"),
	}
	config.configDir = filepath.Join(config.xdgConfigHome, "filezilla")
	cleanup := func() { _ = os.RemoveAll(root) }
	for _, directory := range []string{
		config.dataDir,
		config.xdgConfigHome,
		config.homeDir,
		config.configDir,
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			cleanup()
			return sessionConfig{}, fmt.Errorf("create FileZilla session directory: %w", err)
		}
	}
	defaults := `<?xml version="1.0" encoding="UTF-8" standalone="yes" ?>
<FileZilla3>
  <Settings>
    <Setting name="Config Location">$FLOTTE_FILEZILLA_CONFIG</Setting>
    <Setting name="Kiosk mode">2</Setting>
  </Settings>
</FileZilla3>
`
	for _, path := range []string{
		filepath.Join(config.dataDir, "fzdefaults.xml"),
		filepath.Join(config.xdgConfigHome, "filezilla", "fzdefaults.xml"),
	} {
		if err := writeSessionFile(path, defaults); err != nil {
			cleanup()
			return sessionConfig{}, err
		}
	}
	sitemanager, err := siteManagerXML(site)
	if err != nil {
		cleanup()
		return sessionConfig{}, err
	}
	if err := writeSessionFile(filepath.Join(config.configDir, "sitemanager.xml"), sitemanager); err != nil {
		cleanup()
		return sessionConfig{}, err
	}
	hostkeyXML, err := hostkeyStoreXML(site, hostkeys)
	if err != nil {
		cleanup()
		return sessionConfig{}, err
	}
	if err := writeSessionFile(filepath.Join(config.configDir, "hostkeys.xml"), hostkeyXML); err != nil {
		cleanup()
		return sessionConfig{}, err
	}
	return config, nil
}

func (c sessionConfig) cleanup() {
	_ = os.RemoveAll(c.root)
}

func (c sessionConfig) configureProcess(command *exec.Cmd) {
	environment := command.Env
	if environment == nil {
		environment = os.Environ()
	}
	for _, pair := range [][2]string{
		{"HOME", c.homeDir},
		{"XDG_CONFIG_HOME", c.xdgConfigHome},
		{"FZ_DATADIR", c.dataDir},
		{"FLOTTE_FILEZILLA_CONFIG", c.configDir},
	} {
		environment = setEnvironment(environment, pair[0], pair[1])
	}
	command.Env = environment
}

func writeSessionFile(path, content string) error {
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write FileZilla session file %s: %w", path, err)
	}
	return nil
}

func siteManagerXML(site Site) (string, error) {
	if err := validateSite(site); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\" ?>\n<FileZilla3>\n  <Servers>\n    <Folder expanded=\"1\">Flotte\n      <Server>\n")
	writeXMLText(&b, "Host", site.Host)
	writeXMLText(&b, "Port", fmt.Sprintf("%d", site.Port))
	writeXMLText(&b, "Protocol", "1")
	writeXMLText(&b, "User", site.User)
	writeXMLText(&b, "Logontype", "1")
	writeXMLText(&b, "Name", "session")
	writeXMLParameter(&b, "allow_agent_keys_of_unknown_type", "1")
	b.WriteString("      </Server>\n    </Folder>\n  </Servers>\n</FileZilla3>\n")
	return b.String(), nil
}

func hostkeyStoreXML(site Site, hostkeys []ssh.PublicKey) (string, error) {
	if err := validateSite(site); err != nil {
		return "", err
	}
	if len(hostkeys) == 0 {
		return "", fmt.Errorf("flotte returned no host keys for FileZilla")
	}
	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\" ?>\n<FileZilla3>\n")
	fmt.Fprintf(&b, "  <Server Host=\"%s\" Port=\"%d\">\n", xmlEscapeAttr(strings.ToLower(site.Host)), site.Port)
	for _, key := range hostkeys {
		if key == nil {
			return "", fmt.Errorf("flotte returned an invalid host key for FileZilla")
		}
		writeXMLText(&b, "Hostkey", base64.StdEncoding.EncodeToString(key.Marshal()))
	}
	b.WriteString("  </Server>\n</FileZilla3>\n")
	return b.String(), nil
}

func writeXMLText(b *strings.Builder, name, value string) {
	b.WriteString("        <")
	b.WriteString(name)
	b.WriteByte('>')
	_ = xml.EscapeText(b, []byte(value))
	b.WriteString("</")
	b.WriteString(name)
	b.WriteString(">\n")
}

func writeXMLParameter(b *strings.Builder, name, value string) {
	fmt.Fprintf(b, "        <Parameter Name=\"%s\">", xmlEscapeAttr(name))
	_ = xml.EscapeText(b, []byte(value))
	b.WriteString("</Parameter>\n")
}

func xmlEscapeAttr(value string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(value))
	return strings.NewReplacer("\"", "&#34;", "'", "&#39;").Replace(b.String())
}
