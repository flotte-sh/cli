<div align="center">

# Flotte CLI

**Manage SSH access with short-lived certificates through your Flotte server.**

[Documentation](https://docs.flotte.sh) · [Install](#install) · [Quick Start](#quick-start) · [SSH Integration](#ssh-integration)

</div>

New to Flotte? Learn how to host a server for free at [docs.flotte.sh](https://docs.flotte.sh).

## Install

### Homebrew (macOS and Linux)

```sh
brew tap flotte-sh/tap
brew trust flotte-sh/tap
brew install flotte-cli
```

### APT (Debian and Ubuntu)

```sh
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://apt.flotte.sh/signing-key.gpg | sudo tee /etc/apt/keyrings/flotte.gpg >/dev/null
echo "deb [signed-by=/etc/apt/keyrings/flotte.gpg] https://apt.flotte.sh stable main" | sudo tee /etc/apt/sources.list.d/flotte.list
sudo apt update
sudo apt install flotte
```

Packages are signed with the key `86E4 B3C7 1212 14F2 CD26  D2F4 54FD 2ECF B913 51A9`.

### From source

Requires Go 1.26.9 or newer patched release. Go 1.27 users need 1.27.2 or newer.

```sh
go install github.com/flotte-sh/cli/cmd/flotte@latest
```

Ensure your Go binary directory is on `PATH`.

## Quick Start

```sh
flotte setup https://flotte.example.com
flotte ssh user@host
```

The first setup saves the server URL. Run `flotte setup` again later to reuse it,
for example when enabling shell integration.

To use Flotte with ordinary `ssh`, `scp`, and `sftp`:

```sh
flotte ssh-config install
ssh user@host
```

## Integrations

| Client | Platforms | Command |
| --- | --- | --- |
| OpenSSH (`ssh`, `scp`, `sftp`) | Linux, macOS, Windows | `flotte ssh-config install`, or `flotte ssh user@host` for a single connection |
| FileZilla (3.71.0 or newer) | Linux, macOS, Windows | `flotte filezilla user@host` |
| PuTTY | Windows | `flotte putty user@host` |
| WinSCP | Windows | `flotte winscp user@host` |

## SSH Integration

See the [integration overview](https://docs.flotte.sh/integrations/) and
[OpenSSH guide](https://docs.flotte.sh/integrations/openssh.html) for setup,
authentication flow, credential lifetime, and troubleshooting.

- Requires OpenSSH with `KnownHostsCommand` and `IdentityAgent` support.
- Respects your SSH aliases, users, ports, and jump-host settings.
- Global installation applies to `Host *`: logout, API outages, or unapproved host keys can also disrupt connections to unmanaged hosts.
- For jump hosts that need Flotte certificates, install the integration; `flotte ssh` options are not inherited by jump-host processes.
- Certificates expire; established SSH sessions continue after expiry.
- Use `flotte ssh --legacy user@host` for the older file-based certificate flow.

## Signing In

`flotte setup` and `flotte login` open your browser. After you sign in, Flotte shows a confirmation page that names the account. When you choose Continue, the CLI collects the session from the server, using a secret that never left your computer.

- Confirm only a sign-in you started yourself by running a Flotte command just now.
- If someone sends you a sign-in link, do not open it. Whoever started a sign-in receives the session of the person who confirms it.
- The link works in any browser that reaches the Flotte server, so it also works from a container, WSL or a remote machine: open it on the device that has your browser.
- Choose Cancel on the page to reject a sign-in; the CLI stops waiting.
- A sign-in link works for 5 minutes. After that the server refuses it; run the command again.
- Open the link yourself. A link that another web page opens, for example from web mail or a browser-based terminal, is refused: paste it into the address bar.
- This CLI needs a Flotte server that offers the `consent` sign-in. Older servers must be updated.

The CLI keeps one session and sends it only to the server that issued it:

- After pointing the CLI at another server, sign in again. A session saved by an older CLI is not tied to a server and is no longer used.
- `flotte setup` uses the address a server reports for itself only when it is on the host you entered. Otherwise it stops and prints the command to run.
- Requests that carry the session never follow a redirect. If the server address redirects, run `flotte setup` with the address it redirects to.
- `flotte logout` ends the session on the server that issued it and removes it from this computer. If the server cannot be reached, the session is still removed locally and the CLI warns that it can stay valid on the server until it expires.

## Common Commands

| Command | Purpose |
| --- | --- |
| `flotte login` / `flotte logout` | Sign in or out |
| `flotte config --show` | Show configuration |
| `flotte completion install [bash\|zsh\|fish]` | Install shell completion |
| `flotte completion uninstall [bash\|zsh\|fish]` | Remove shell completion |
| `flotte uninstall` | Remove managed SSH integration, shell completions and the session |
| `flotte <command> --help` | Show options and examples |

`flotte uninstall` keeps the binary, account configuration, SSH keys, and
unrelated SSH settings. It always removes the session from this computer and
ends it on the server; if the server cannot be reached it prints a warning,
because the session can then stay valid there until it expires. Restart your
shell after removing completions.

## Requesting an Integration

Need Flotte to work with another SSH client or tool? Check the
[integration overview](https://docs.flotte.sh/integrations/) first, then
[open an integration request](https://github.com/flotte-sh/cli/issues/new?template=integration_request.md).

## Security and License

Report security issues privately to [support@flotte.sh](mailto:support@flotte.sh).
Licensed under MIT with Commons Clause; see [License](License).
