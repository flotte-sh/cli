package openssh

import (
	"reflect"
	"testing"
)

func TestParseSSHArguments(t *testing.T) {
	for _, test := range []struct {
		name       string
		args       []string
		wantLegacy bool
		wantRest   []string
	}{
		{name: "no flag", args: []string{"-p", "2222", "root@example.com"}, wantLegacy: false, wantRest: []string{"-p", "2222", "root@example.com"}},
		{name: "standalone flag", args: []string{"--legacy", "root@example.com"}, wantLegacy: true, wantRest: []string{"root@example.com"}},
		{name: "separated -o form", args: []string{"-o", "legacy", "root@example.com"}, wantLegacy: true, wantRest: []string{"root@example.com"}},
		{name: "joined -o form", args: []string{"-olegacy", "root@example.com"}, wantLegacy: true, wantRest: []string{"root@example.com"}},
		{name: "unrelated -o value passes through", args: []string{"-o", "legacy=off", "root@example.com"}, wantLegacy: false, wantRest: []string{"-o", "legacy=off", "root@example.com"}},
		{name: "unrelated joined -o passes through", args: []string{"-oVerifyHostKeyDNS=yes", "root@example.com"}, wantLegacy: false, wantRest: []string{"-oVerifyHostKeyDNS=yes", "root@example.com"}},
		{name: "flag after options", args: []string{"-p", "2222", "--legacy", "root@example.com"}, wantLegacy: true, wantRest: []string{"-p", "2222", "root@example.com"}},
		{name: "joined option value ending in value-taking character", args: []string{"-oStrictHostKeyChecking=no", "--legacy", "root@example.com"}, wantLegacy: true, wantRest: []string{"-oStrictHostKeyChecking=no", "root@example.com"}},
		{name: "joined login name ending in value-taking character", args: []string{"-lmarco", "root@example.com", "--legacy"}, wantLegacy: false, wantRest: []string{"-lmarco", "root@example.com", "--legacy"}},
		{name: "joined port after destination", args: []string{"-p2222", "root@example.com", "--legacy"}, wantLegacy: false, wantRest: []string{"-p2222", "root@example.com", "--legacy"}},
		{name: "bundled flags then separated value", args: []string{"-4vp", "2222", "root@example.com"}, wantLegacy: false, wantRest: []string{"-4vp", "2222", "root@example.com"}},
		{name: "separated value then joined flag", args: []string{"-p", "2222", "-oStrictHostKeyChecking=no", "root@example.com"}, wantLegacy: false, wantRest: []string{"-p", "2222", "-oStrictHostKeyChecking=no", "root@example.com"}},
		{name: "flag text after -- separator preserved", args: []string{"--legacy", "root@example.com", "--", "echo", "--legacy"}, wantLegacy: true, wantRest: []string{"root@example.com", "--", "echo", "--legacy"}},
		{name: "flag between option groups", args: []string{"-p", "2222", "--legacy", "-o", "Foo=bar", "root@example.com"}, wantLegacy: true, wantRest: []string{"-p", "2222", "-o", "Foo=bar", "root@example.com"}},
		{name: "separated option value containing spaces", args: []string{"-o", "ProxyCommand=ssh -W %h:%p bastion", "--legacy", "root@example.com"}, wantLegacy: true, wantRest: []string{"-o", "ProxyCommand=ssh -W %h:%p bastion", "root@example.com"}},
		{name: "repeated flag", args: []string{"--legacy", "--legacy", "root@example.com"}, wantLegacy: true, wantRest: []string{"root@example.com"}},
		{name: "bundled no-arg flags then flag", args: []string{"-4vq", "--legacy", "root@example.com"}, wantLegacy: true, wantRest: []string{"-4vq", "root@example.com"}},
		{name: "bundled flags with joined value then flag", args: []string{"-4voFoo=bar", "--legacy", "root@example.com"}, wantLegacy: true, wantRest: []string{"-4voFoo=bar", "root@example.com"}},
		{name: "bundled value option consumes following value then flag", args: []string{"-4vp", "2222", "--legacy", "root@example.com"}, wantLegacy: true, wantRest: []string{"-4vp", "2222", "root@example.com"}},
		{name: "flag after destination preserved", args: []string{"-p", "2222", "root@example.com", "--legacy"}, wantLegacy: false, wantRest: []string{"-p", "2222", "root@example.com", "--legacy"}},
		{name: "dash destination stops option parsing", args: []string{"-p", "2222", "-", "--legacy"}, wantLegacy: false, wantRest: []string{"-p", "2222", "-", "--legacy"}},
		{name: "empty", args: nil, wantLegacy: false, wantRest: nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			assertParseSSHArguments(t, test.args, test.wantLegacy, test.wantRest)
		})
	}
}

// sshValueTakingOptions mirrors the flags in ssh(1) that take a value.
var sshValueTakingOptions = []struct {
	flag  string
	value string
}{
	{"-B", "192.0.2.1"},
	{"-b", "192.0.2.2"},
	{"-c", "aes256-ctr"},
	{"-D", "1080"},
	{"-E", "/tmp/ssh.log"},
	{"-e", "^"},
	{"-F", "/tmp/ssh_config"},
	{"-I", "/tmp/pkcs11"},
	{"-i", "/tmp/id_ed25519"},
	{"-J", "bastion"},
	{"-L", "8080:localhost:80"},
	{"-l", "root"},
	{"-m", "hmac-sha2-256"},
	{"-O", "check"},
	{"-o", "Foo=bar"},
	{"-P", "sometag"},
	{"-p", "2222"},
	{"-Q", "cipher"},
	{"-R", "9090:localhost:90"},
	{"-S", "/tmp/control"},
	{"-W", "example.com:22"},
	{"-w", "0:0"},
}

func TestParseSSHArgumentsSeparatedOptionValues(t *testing.T) {
	for _, option := range sshValueTakingOptions {
		t.Run(option.flag, func(t *testing.T) {
			args := []string{option.flag, option.value, "--legacy", "root@example.com"}
			assertParseSSHArguments(t, args, true, []string{option.flag, option.value, "root@example.com"})
		})
	}
}

func TestParseSSHArgumentsJoinedOptionValues(t *testing.T) {
	for _, option := range sshValueTakingOptions {
		t.Run(option.flag, func(t *testing.T) {
			token := option.flag + option.value
			args := []string{token, "--legacy", "root@example.com"}
			assertParseSSHArguments(t, args, true, []string{token, "root@example.com"})
		})
	}
}

func TestParseSSHArgumentsAllOptionValues(t *testing.T) {
	separated := make([]string, 0, 2*len(sshValueTakingOptions)+2)
	joined := make([]string, 0, len(sshValueTakingOptions)+2)
	wantSeparatedRest := make([]string, 0, 2*len(sshValueTakingOptions)+1)
	wantJoinedRest := make([]string, 0, len(sshValueTakingOptions)+1)
	for _, option := range sshValueTakingOptions {
		separated = append(separated, option.flag, option.value)
		wantSeparatedRest = append(wantSeparatedRest, option.flag, option.value)
		joined = append(joined, option.flag+option.value)
		wantJoinedRest = append(wantJoinedRest, option.flag+option.value)
	}
	separated = append(separated, "--legacy", "root@example.com")
	joined = append(joined, "--legacy", "root@example.com")
	wantSeparatedRest = append(wantSeparatedRest, "root@example.com")
	wantJoinedRest = append(wantJoinedRest, "root@example.com")

	t.Run("separated", func(t *testing.T) {
		assertParseSSHArguments(t, separated, true, wantSeparatedRest)
	})
	t.Run("joined", func(t *testing.T) {
		assertParseSSHArguments(t, joined, true, wantJoinedRest)
	})
}

func assertParseSSHArguments(t *testing.T, args []string, wantLegacy bool, wantRest []string) {
	t.Helper()
	mode, rest := parseSSHArguments(args)
	if legacy := mode == sshModeLegacy; legacy != wantLegacy {
		t.Fatalf("legacy = %v, want %v", legacy, wantLegacy)
	}
	if !reflect.DeepEqual(rest, wantRest) {
		t.Fatalf("rest = %v, want %v", rest, wantRest)
	}
}
