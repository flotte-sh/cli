package filezilla

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/flotte-sh/flotte-cli/integrations/internal/target"
)

type Site struct {
	Host string
	Port int
	User string
}

func NewSite(user, address string) (Site, error) {
	if user == "" || !utf8.ValidString(user) || strings.ContainsFunc(user, unicode.IsControl) {
		return Site{}, fmt.Errorf("invalid FileZilla username")
	}
	host, port, err := target.Split(address)
	if err != nil {
		return Site{}, fmt.Errorf("invalid FileZilla target: %w", err)
	}
	if strings.HasPrefix(address, "[") {
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.Is6() {
			return Site{}, fmt.Errorf("invalid FileZilla IPv6 host")
		}
	}
	site := Site{Host: host, Port: port, User: user}
	if err := validateSite(site); err != nil {
		return Site{}, err
	}
	return site, nil
}

func validateSite(site Site) error {
	if site.Host == "" || site.User == "" || site.Port < 1 || site.Port > 65535 || !utf8.ValidString(site.Host) || !utf8.ValidString(site.User) || strings.ContainsFunc(site.User, unicode.IsControl) {
		return fmt.Errorf("invalid FileZilla SFTP target")
	}
	if strings.Contains(site.Host, ":") {
		address, err := netip.ParseAddr(site.Host)
		if err != nil || !address.Is6() {
			return fmt.Errorf("invalid FileZilla IPv6 host")
		}
	}
	if _, _, err := target.Split(net.JoinHostPort(site.Host, strconv.Itoa(site.Port))); err != nil {
		return fmt.Errorf("invalid FileZilla target: %w", err)
	}
	return nil
}
