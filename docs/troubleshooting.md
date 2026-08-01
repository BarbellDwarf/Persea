# Troubleshooting

## guacd

### guacd won't start
- Check `systemctl status rustguac-guacd`
- Check logs: `journalctl -u rustguac-guacd -n 50`
- Verify FreeRDP plugins: `ls /opt/rustguac/lib/freerdp3/`
- Common: missing `LD_LIBRARY_PATH` — the systemd service sets this automatically

### guacd connection refused
- Verify guacd is listening: `ss -tlnp | grep 4822`
- Check TLS certs exist: `ls /opt/rustguac/tls/`
- Verify config has `guacd_addr = "127.0.0.1:4822"`

## rustguac

### Server won't start
- Check `systemctl status rustguac`
- Verify config: `rustguac --config /opt/rustguac/config.toml serve`
- Common: port 8089 already in use — check `ss -tlnp | grep 8089`

### WebSocket connection fails
- Check if rate limiting is enabled and blocking
- Verify `allowed_networks` includes your IP
- Check browser console for WebSocket errors

### Sessions fail to connect
- Verify guacd is running and reachable
- Check session timeout settings
- Verify target host is reachable from the server

## Web browser sessions

### Chromium won't start
- Verify `chromium` is installed: `which chromium`
- Check the `rustguac` user has a home directory: `ls -la /home/rustguac`
- Common: missing `--in-process-gpu` flag — check Chromium flags in config
- Check Xvnc: `ps aux | grep Xvnc`

### Black screen in browser session
- Chromium may have crashed — check logs
- Verify DISPLAY variable is set correctly
- Check available display numbers in config (`display_range_start/end`)

## VDI

### Container won't start
- Verify Docker is running: `docker ps`
- Check the `rustguac` user is in the `docker` group
- Verify the VDI image exists: `docker images | grep vdi`
- Check container logs: `docker logs rustguac-vdi-{username}`

## Database

### SQLite locked errors
- Only one process can write at a time
- Check for stale lock files
- Verify the db_path in config is writable

## OIDC

### Login callback fails
- Verify `redirect_uri` matches your OIDC provider configuration
- Check `OIDC_CLIENT_SECRET` environment variable
- Verify issuer URL is reachable from the server

## Vault / OpenBao

### "403 Forbidden" from Vault
- Check that the role_id and secret_id are correct
- Verify the policy is attached: `vault read auth/approle/role/rustguac`
- Check token hasn't expired: `vault token lookup`
- If using namespaces, ensure the policy was created inside the namespace

### "connection refused" when connecting to Vault
- Verify Vault is running: `vault status`
- Check Vault is unsealed: `vault status` shows `Sealed: false`
- Verify the address in config.toml matches Vault's listen address
- Check firewall rules if Vault is on a different host

### VAULT_SECRET_ID not set
- The secret_id must be in the environment where rustguac runs
- For systemd: add to `/opt/rustguac/env` file
- For Docker: pass as `-e VAULT_SECRET_ID=...` or use Docker secrets
- Check: `systemctl show rustguac | grep Environment`

### Token renewal failures
- Check rustguac logs for "Vault: token renewal failed"
- If 403 on renewal, the token expired — rustguac will re-authenticate automatically
- If persistent, verify the AppRole secret_id hasn't been revoked

### Namespace mismatch
- The `namespace` field in config.toml must match the Vault namespace where AppRole is enabled
- CLI commands must target the namespace: `vault namespace exec -namespace=admin -- vault policy write ...`

### mTLS errors
- Verify CA cert is correct: `openssl s_client -connect vault:8200 -CAfile ca.pem`
- Check client cert hasn't expired: `openssl x509 -in client.pem -noout -dates`
- Ensure the cert's CN matches what Vault's cert auth backend expects
