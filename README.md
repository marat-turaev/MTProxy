# MTProxy
Simple MT-Proto proxy

## Building
Install dependencies, you would need common set of tools for building from source, and development packages for `openssl` and `zlib`.

On Debian/Ubuntu:
```bash
apt install git curl build-essential libssl-dev zlib1g-dev
```
On CentOS/RHEL:
```bash
yum install openssl-devel zlib-devel
yum groupinstall "Development Tools"
```

Clone the repo:
```bash
git clone https://github.com/TelegramMessenger/MTProxy
cd MTProxy
```

To build, simply run `make`, the binary will be in `objs/bin/mtproto-proxy`:

```bash
make && cd objs/bin
```

If the build has failed, you should run `make clean` before building it again.

## Running
1. Obtain a secret, used to connect to telegram servers.
```bash
curl -s https://core.telegram.org/getProxySecret -o proxy-secret
```
2. Obtain current telegram configuration. It can change (occasionally), so we encourage you to update it once per day.
```bash
curl -s https://core.telegram.org/getProxyConfig -o proxy-multi.conf
```
3. Generate a secret to be used by users to connect to your proxy.
```bash
head -c 16 /dev/urandom | xxd -ps
```
4. Run `mtproto-proxy`:
```bash
./mtproto-proxy -u nobody -p 8888 -H 443 -S <secret> --http-stats --aes-pwd proxy-secret proxy-multi.conf -M 1
```
... where:
- `nobody` is the username. `mtproto-proxy` calls `setuid()` to drop privileges.
- `443` is the port, used by clients to connect to the proxy.
- `8888` is the local port (loopback-only). You can use it to get statistics from `mtproto-proxy` (enable with `--http-stats`). Like `wget localhost:8888/stats`.
- `<secret>` is the secret generated at step 3. Also you can set multiple secrets: `-S <secret1> -S <secret2>`.
- `proxy-secret` and `proxy-multi.conf` are obtained at steps 1 and 2.
- `1` is the number of worker processes (`-M`). For TLS-transport mode (`-D`), a single worker is usually preferred.

Also feel free to check out other options using `mtproto-proxy --help`.

Note:
- `/stats` is only served to loopback clients (`127.0.0.1` / `::1`) and the local port (`-p`) is loopback-only. If you need remote access, use an SSH tunnel instead of exposing the stats port.

5. Generate the link with following schema: `tg://proxy?server=SERVER_NAME&port=PORT&secret=SECRET` (or let the official bot generate it for you).
6. Register your proxy with [@MTProxybot](https://t.me/MTProxybot) on Telegram.
7. Set received tag with arguments: `-P <proxy tag>`
8. Enjoy.

## Random padding
Due to some ISPs detecting MTProxy by packet sizes, random padding is
added to packets if such mode is enabled.

It's only enabled for clients which request it.

Add `dd` prefix to secret (`cafe...babe` => `ddcafe...babe`) to enable
this mode on client side (classic transport mode).

In TLS-transport mode (`-D`), clients use:
`ee<secret_hex><domain_hex>`

## TLS-transport mode (-D)
The proxy also supports "TLS-transport" mode. In this mode, the proxy only
accepts TLS-looking connections with SNI matching an allowed domain.

To enable it, add one or more `-D <domain>` options when starting the proxy:
```bash
./mtproto-proxy -u nobody -p 8888 -H 443 -S <secret> -D example.com --aes-pwd proxy-secret proxy-multi.conf -M 1
```
Notes:
- You can specify `-D` multiple times (allowlist). The first `-D` domain is used as default.
- When `-D` is used, other transports are disabled (TLS-transport only).
- On startup, the proxy may make outbound connections to the configured domains to learn realistic TLS response sizing. If that fails, it falls back to defaults.
- Connections that stay undetermined are closed quickly (short timeout) to keep resource usage bounded.

### Connection handling in TLS-transport mode
Without `--fallback-backend`:
- MTProxy TLS-transport connections are served normally.
- Plain HTTP requests get a `301 Moved Permanently` redirect to `https://<first -D domain>/...`.
- Other non-MTProxy traffic is rejected/closed in a standard way.

With `--fallback-backend`:
- Non-MTProxy traffic is proxied (TCP passthrough) to the configured local backend.

### Fallback backend (--fallback-backend)
In TLS-transport mode (`-D`), you can optionally configure a local fallback backend:
```bash
./mtproto-proxy ... -D example.com --fallback-backend 127.0.0.1:8443
```
Behavior:
- Non-MTProxy connections on a TLS-only listener (for example: plain HTTP, regular TLS handshakes that are not TLS-transport) are proxied (TCP passthrough) to the fallback backend.
- This can be used to serve content on the same port (for example: an HTTPS site or landing page).

Security note:
- Be careful: `--fallback-backend` can unintentionally expose an internal service to the Internet. This fork only allows loopback targets (`127.0.0.1:<port>` or `[::1]:<port>`) to reduce the chance of misconfiguration; do not point it at admin panels/databases/metadata endpoints.

### IP allowlist / blocklist (CIDR ACL)
This fork supports file-based client IP ACLs with periodic reload:

```bash
./mtproto-proxy ... \
  --ip-allowlist-file /etc/telegram/ip-allowlist.txt \
  --ip-blocklist-file /etc/telegram/ip-blocklist.txt \
  --ip-acl-refresh-interval 60
```

Behavior:
- `--ip-allowlist-file`: if set, only client IPs from this file are allowed.
- `--ip-blocklist-file`: if set, client IPs from this file are denied.
- If both are set, allowlist check is applied first, then blocklist.
- ACL checks are performed early on accepted connections (before expensive handshake work).
- Reload is based on file mtime/size and runs every `--ip-acl-refresh-interval` seconds (`0` disables periodic refresh).

File format:
- One IPv4/IPv6 address or CIDR per line.
- `#` starts a comment.
- Empty lines are ignored.
- Examples:
```text
# IPv4
203.0.113.0/24
198.51.100.10

# IPv6
2001:db8::/32
2001:db8:1234::1
```

Operational note:
- Current implementation is file-based only. If you use remote feeds, fetch them externally (cron/systemd timer), validate/sanitize, then atomically replace the local file.

Client secret format for TLS-transport is:
`ee<secret_hex><domain_hex>`

Where `<domain_hex>` is the ASCII domain name encoded as hex, for example:
```bash
echo -n example.com | xxd -ps
```

## Systemd example configuration
1. Create systemd service file (it's standard path for the most Linux distros, but you should check it before):
```bash
nano /etc/systemd/system/MTProxy.service
```
2. Edit this basic service (especially paths and params):
```bash
[Unit]
Description=MTProxy
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/MTProxy
ExecStart=/opt/MTProxy/mtproto-proxy -u nobody -p 8888 -H 443 -S <secret> -P <proxy tag> <other params>
Restart=on-failure

[Install]
WantedBy=multi-user.target
```
3. Reload daemons:
```bash
systemctl daemon-reload
```
4. Test fresh MTProxy service:
```bash
systemctl restart MTProxy.service
# Check status, it should be active
systemctl status MTProxy.service
```
5. Enable it, to autostart service after reboot:
```bash
systemctl enable MTProxy.service
```

## Docker image
Telegram is also providing [official Docker image](https://hub.docker.com/r/telegrammessenger/proxy/).
Note: the image is outdated.
