# Security

## Reporting a vulnerability

Please do **not** open a public issue. Use GitHub's private vulnerability reporting (Security tab → "Report a vulnerability"). You will get an answer within a few days.

## Threat model

The code is public, so nothing here relies on obscurity. The programs are meant for a home server on a trusted network (LAN / VPN), optionally publishing apps through a Cloudflare Tunnel.

Trusted: the administrator, and the operating system.
Partially trusted: the optional "manager" account of homelabOS (can see metrics and use Hosting, nothing else) and any other account the login provider reports. They can deploy apps but, by default, **only containers**.
Untrusted: anyone on the network, anyone on the internet reaching a published app, the code of hosted apps and of repositories you deploy.

## What is protected

| Area | Protection |
|---|---|
| Login | PBKDF2-HMAC-SHA256 600k iterations; constant-time comparison; same cost for unknown users; 5 failures lock an IP for 15 min; 7-day random 128-bit sessions; cookie `HttpOnly; SameSite=Strict` (+`Secure` behind HTTPS) |
| CSRF | All state-changing requests need `X-Requested-With`. Cookies do not isolate ports, so a page served on another port of the same host counts as "same site"; the header requires a CORS preflight that is never granted |
| Session theft by apps | The Hosting proxy removes the panel cookie (`hl`) before forwarding requests to apps |
| Startup | No password → refuses to listen on anything but loopback; weak/old hash formats are reported |
| Slow clients | 10 s total budget for request headers, bounded body reads, connection caps |
| File manager | Paths resolved with `realpath` and kept inside the shared root (symlinks pointing out are refused); uploads cannot contain `/` in names; user files are served as inert text (`CSP: sandbox`) |
| Hosting: config injection | Tokens and hostnames are validated; values written to the `curl -K` config and to the tunnel YAML are escaped or rejected, so no extra directives can be smuggled in |
| Hosting: uploads | Archives with absolute paths or `..` are rejected whole; links, devices and FIFOs are dropped; 50k files / 2 GB extracted limit; a `Dockerfile` that is a symlink is not used |
| Hosting: secrets | Never in `argv` (visible to every local user): SQL with passwords goes through stdin, container variables through the environment, the Cloudflare/GitHub tokens through stdin/headers. Random secrets use `getrandom` and abort on failure |
| Hosting: privilege | Build and start commands run on the host only for the administrator (and users listed in `native_users`); others are forced to containers |
| Hosting: native apps | Landlock sandbox (read-only system, private `HOME`, writable only in the app folder and `/tmp`) and `no_new_privs`, so `data/` (API token, Cloudflare/GitHub tokens, DB credentials), `~/.cloudflared`, `~/.ssh` and `sudo` are out of reach |
| Hosting: containers | Rootless Podman, memory limit, 1024-PID limit, `no-new-privileges`, `NET_RAW` dropped, published on loopback only (the counting proxy opens the public port) |
| Hosting: DNS | An existing Cloudflare record that does not already point to this tunnel is never overwritten |
| Hosting: databases | Each database is closed to `PUBLIC`; the admin credentials live in `data/` (outside the sandbox) instead of a superuser reachable over the local socket |
| Hosting: statistics | IPs are never written, only a per-day salted hash; bots and errors are not counted as visitors |

## What is NOT protected (read this)

- **Native apps are best-effort isolation, not a security boundary.** Landlock does not restrict outbound network access, and connecting to existing local sockets or processes of the same user is only partly restricted depending on kernel version. Run code you do not trust in a **container**, or leave `native_users` empty.
- Kernels without Landlock (< 5.13) run native apps unsandboxed (the log and the startup line say so).
- Plain HTTP on the LAN: anyone who can sniff the network can read the session cookie. Use a VPN or TLS.
- Without `db-admin.sh`, Hosting falls back to the old mode in which the service user is a database superuser over the local socket, reachable by every process of that user. Run `deploy/db-admin.sh`.
- A compromised administrator account owns the server by design (it can run commands).
- Cookie *tossing*: an app can set a cookie named `hl` for the shared host and log users out (it cannot read or steal the real one).

## Hardening checklist for operators

1. Keep `bind` on a private interface; do not port-forward the panels. Publish only apps, through the tunnel.
2. Run `deploy/db-admin.sh` and delete any database role for the service user.
3. Leave `native_users` empty unless you fully trust those people.
4. Use fine-grained, read-only GitHub tokens.
5. Run the services as the dedicated user created by `deploy/install.sh`, not your personal account.
6. Keep the kernel, Podman and `cloudflared` updated.
