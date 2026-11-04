<div align="center">

# Flotte CLI

**Manage SSH access with short-lived certificates through your Flotte server.**

[Documentation](https://docs.flotte.sh) · [Install](#install) · [Quick Start](#quick-start) · [SSH Integration](#ssh-integration)

</div>

New to Flotte? Learn how to host a server for free at [docs.flotte.sh](https://docs.flotte.sh).

## Install

Requires Go 1.26.9 or newer patched release. Go 1.27 users need 1.27.2 or newer.

From the CLI repository (or the `cli/` directory of the main repository):

```sh
go install ./cmd/flotte
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

## Common Commands

| Command | Purpose |
| --- | --- |
| `flotte login` / `flotte logout` | Sign in or out |
| `flotte config --show` | Show configuration |
| `flotte completion install [bash\|zsh\|fish]` | Install shell completion |
| `flotte completion uninstall [bash\|zsh\|fish]` | Remove shell completion |
| `flotte uninstall` | Remove managed SSH integration and shell completions |
| `flotte <command> --help` | Show options and examples |

`flotte uninstall` keeps the binary, account configuration, SSH keys, and
unrelated SSH settings. Restart your shell after removing completions.

## Requesting an Integration

Need Flotte to work with another SSH client or tool? Check the
[integration overview](https://docs.flotte.sh/integrations/) first, then
[open an integration request](https://github.com/flotte-sh/cli/issues/new?template=integration_request.md).

## Security and License

Report security issues privately to [support@flotte.sh](mailto:support@flotte.sh).
Licensed under MIT with Commons Clause; see [License](License).
