# sshwebdoor

sshwebdoor is a Go-based single-port SSH and HTTPS gateway. It inspects the first packet on an inbound TCP connection to determine whether to serve a hardened HTTPS password challenge or proxy the session to the local OpenSSH daemon.

## Features

- Single port for both HTTPS and SSH detection
- Built-in HTTPS password page with lockout mechanics
- Transparent TCP forwarding to loopback-restricted sshd
- Interactive `init` command that prepares configuration and optional sshd loopback restriction
- `install` helper to register sshwebdoor as a systemd service
- `serve` daemon entrypoint suitable for systemd

## Getting Started

```bash
go build ./...
./sshwebdoor init
sudo ./sshwebdoor install
```

The configuration is stored at `/etc/sshwebdoor/config.yaml` by default. Once installed, manage the daemon using `systemctl status|restart sshwebdoor`.
