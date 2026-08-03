# Troubleshooting

## guacd

### guacd won't start
- Check `systemctl status persea-guacd`
- Check logs: `journalctl -u persea-guacd -n 50`
- Verify FreeRDP plugins: `ls /opt/persea/lib/freerdp3/`
- Common: missing `LD_LIBRARY_PATH` — the systemd service sets this automatically

### guacd connection refused
- Verify guacd is listening: `ss -tlnp | grep 4822`
- Check TLS certs exist: `ls /opt/persea/tls/`
- Verify config has `guacd_addr = "127.0.0.1:4822"`

## persea

### Server won't start
- Check `systemctl status persea`
- Verify config: `persea --config /opt/persea/config.toml serve`
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
- Check the `persea` user has a home directory: `ls -la /home/persea`
- Common: missing `--in-process-gpu` flag — check Chromium flags in config
- Check Xvnc: `ps aux | grep Xvnc`

### Black screen in browser session
- Chromium may have crashed — check logs
- Verify DISPLAY variable is set correctly
- Check available display numbers in config (`display_range_start/end`)

## VDI

### Container won't start
- Verify Docker is running: `docker ps`
- Check the `persea` user is in the `docker` group
- Verify the VDI image exists: `docker images | grep vdi`
- Check container logs: `docker logs persea-vdi-{username}`

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
- Verify the policy is attached: `vault read auth/approle/role/persea`
- Check token hasn't expired: `vault token lookup`
- If using namespaces, ensure the policy was created inside the namespace

### "connection refused" when connecting to Vault
- Verify Vault is running: `vault status`
- Check Vault is unsealed: `vault status` shows `Sealed: false`
- Verify the address in config.toml matches Vault's listen address
- Check firewall rules if Vault is on a different host

### VAULT_SECRET_ID not set
- The secret_id must be in the environment where persea runs
- For systemd: add to `/opt/persea/env` file
- For Docker: pass as `-e VAULT_SECRET_ID=...` or use Docker secrets
- Check: `systemctl show persea | grep Environment`

### Token renewal failures
- Check persea logs for "Vault: token renewal failed"
- If 403 on renewal, the token expired — persea will re-authenticate automatically
- If persistent, verify the AppRole secret_id hasn't been revoked

### Namespace mismatch
- The `namespace` field in config.toml must match the Vault namespace where AppRole is enabled
- CLI commands must target the namespace: `vault namespace exec -namespace=admin -- vault policy write ...`

### mTLS errors
- Verify CA cert is correct: `openssl s_client -connect vault:8200 -CAfile ca.pem`
- Check client cert hasn't expired: `openssl x509 -in client.pem -noout -dates`
- Ensure the cert's CN matches what Vault's cert auth backend expects
