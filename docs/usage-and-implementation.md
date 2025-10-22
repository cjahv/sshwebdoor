# sshwebdoor Usage Scenario and Technical Implementation

## End-to-End Usage Scenario

### 1. Interactive Initialization
1. Administrator fetches or builds the `sshwebdoor` binary on a systemd-based Linux host.
2. Runs `sshwebdoor init`, which starts a guided wizard:
   - Prompt for the single exposed listening address/port (e.g., `0.0.0.0:8443`).
   - Prompt for the secret web password twice; the tool stores only a bcrypt hash in `/etc/sshwebdoor/config.yaml`.
   - Ask whether to keep OpenSSH reachable from all interfaces or restrict it to loopback only. If the loopback option is selected, the wizard rewrites `/etc/ssh/sshd_config` (or `/etc/ssh/sshd_config.d/sshwebdoor.conf`) to set `ListenAddress 127.0.0.1` and reloads the daemon so only `sshwebdoor` can reach it.
   - Generate any additional defaults (log directory, lockout window, forward target). All configuration is persisted in YAML.

### 2. Service Installation
1. Administrator executes `sshwebdoor install`:
   - Binary is copied to `/usr/local/bin/sshwebdoor` (unless already present).
   - A systemd unit file `/etc/systemd/system/sshwebdoor.service` is written with `ExecStart=/usr/local/bin/sshwebdoor serve`.
   - `systemctl daemon-reload`, `systemctl enable sshwebdoor`, and `systemctl start sshwebdoor` are run to activate the daemon.
2. From this point onward, only one TCP port is exposed to the outside world for both HTTPS and SSH probes.

### 3. Day-to-Day Operation
- **Web/TLS probing**: Visiting `https://<host>:<port>/` triggers TLS detection, and the service responds with a built-in HTML page asking for the secret password. The interface displays remaining attempts (three total) and a one-minute countdown after three failures. A successful submission resets the attempt counter and grants access to the follow-up page (e.g., an audit or access confirmation screen).
- **SSH access**: Running `ssh user@host -p <port>` sends an SSH handshake. Because the first packet does not match TLS framing, `sshwebdoor` immediately tunnels the stream to `127.0.0.1:<ssh_port>` (typically 22). From the client’s perspective the handshake behaves like a direct SSH connection.
- **Lockout recovery**: After the lockout timer expires, HTTPS visitors can try the password again without requiring any manual administrator action.

### 4. Maintenance
- Administrators may rerun `sshwebdoor init` to rotate the password hash or change networking policies. The command rewrites the configuration atomically and prompts to restart the systemd service.
- Routine operations rely on `journalctl -u sshwebdoor` and `systemctl status|restart sshwebdoor`.

## Technical Implementation Overview

### Component Architecture
- **CLI entrypoint** (e.g., using `spf13/cobra`) provides subcommands: `init`, `install`, and `serve`.
- **Configuration loader** reads `/etc/sshwebdoor/config.yaml` into a struct containing:
  ```yaml
  listen_address: "0.0.0.0:8443"
  ssh_forward: "127.0.0.1:22"
  password_hash: "<bcrypt>"
  max_attempts: 3
  lockout_seconds: 60
  attempt_window_seconds: 300
  ssh_mode: "loopback" # or "unchanged"
  ```
- **Daemon (`serve`)** orchestrates the TCP listener, TLS detection, HTTP handler, attempt tracking, and SSH proxy.

### Protocol Detection & Routing
1. Accept a TCP connection with `net.Listen("tcp", listenAddress)`.
2. Peek at the first few bytes using a buffered reader.
   - TLS ClientHello begins with `0x16 0x03 0x01/0x03/0x02` etc. Checking the first byte for `0x16` (Handshake) and the record type for TLS version suffices for differentiation.
3. If the stream is TLS:
   - Wrap the connection with `tls.Server` using a locally generated or configured certificate.
   - Serve the HTML password page via `net/http`, rendering attempts/lockout state.
4. If the stream is not TLS:
   - Dial `ssh_forward` with `net.DialTimeout`.
   - Use `io.Copy` in both directions to proxy the raw SSH session.

### Password Validation & Lockout
- Password hashes are verified with `golang.org/x/crypto/bcrypt.CompareHashAndPassword`.
- Attempt counters are tracked per remote address in-memory, persisted optionally to disk to survive restarts.
- After `max_attempts` failures within `attempt_window_seconds`, the remote address enters a lockout map storing the unlock timestamp. HTTP responses render the remaining lockout time.

### Web Interface
- HTML template embedded via Go `//go:embed` directive.
- Single-page form posts password using HTTPS `POST /login`.
- Server responses use JSON or HTML partial updates to indicate success, remaining attempts, or lockout.
- Optional CSRF token generated per session to prevent form replays.

### SSH Forwarding Path
- When OpenSSH is restricted to loopback, `/etc/ssh/sshd_config` is updated to include:
  ```
  ListenAddress 127.0.0.1
  Port 22
  ```
- The daemon proxies without interpreting SSH payloads, keeping latency minimal.
- Idle timeout management closes hung tunnels after a configurable duration.

### Systemd Integration
- Unit file example:
  ```ini
  [Unit]
  Description=sshwebdoor single-port SSH/HTTPS gateway
  After=network.target ssh.service

  [Service]
  ExecStart=/usr/local/bin/sshwebdoor serve --config /etc/sshwebdoor/config.yaml
  Restart=on-failure
  User=sshwebdoor
  Group=sshwebdoor
  AmbientCapabilities=CAP_NET_BIND_SERVICE

  [Install]
  WantedBy=multi-user.target
  ```
- `install` subcommand ensures the service user/group exist and sets ownership on `/etc/sshwebdoor` and log directories.

### Logging & Auditing
- Structured logs (JSON) capture events: TLS detections, failed password attempts, lockouts, SSH tunnel sessions.
- `journalctl` integration plus optional file logging under `/var/log/sshwebdoor/sshwebdoor.log`.
- Potential future enhancement: forward logs to syslog or an HTTP webhook for alerting.

### Security Considerations
- Enforce TLS certificates (self-signed during init or user-provided). Self-signed certs can be generated using Go’s `crypto/tls` helper or `openssl`.
- Rate limiting on HTTPS endpoint mitigates brute-force attempts; integrate with `x/time/rate` if necessary.
- Config and logs are readable only by the `sshwebdoor` service account to protect the password hash and audit trail.
- Provide `sshwebdoor status` command to display lockout state and currently proxied sessions for administrative visibility.

### Future Extensibility Hooks
- Support multiple administrator passwords or hardware tokens by abstracting the authenticator interface.
- Allow optional mTLS for the HTTPS path, requiring client certificates before showing the password form.
- Add metrics endpoint (e.g., Prometheus) for monitoring connection counts, lockouts, and latency.
