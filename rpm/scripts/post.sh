#!/bin/sh
# persea RPM %post scriptlet — cert bootstrap, SELinux, firewalld.
# The cert + secure_cookies logic mirrors install.sh / debian/postinst.
set -e

# Ensure data directories have correct ownership
chown -R persea:persea /opt/persea/data
chown -R persea:persea /opt/persea/recordings

# Generate a self-signed TLS certificate if none exists
if [ ! -f /opt/persea/tls/cert.pem ] || [ ! -f /opt/persea/tls/key.pem ]; then
    CERT_HOSTNAME=$(hostname -f 2>/dev/null || hostname 2>/dev/null || cat /proc/sys/kernel/hostname)
    echo "Generating self-signed TLS certificate for ${CERT_HOSTNAME}..."
    /opt/persea/bin/persea generate-cert \
        --hostname "$CERT_HOSTNAME" \
        --out-dir /opt/persea/tls
    chmod 600 /opt/persea/tls/key.pem
    chmod 644 /opt/persea/tls/cert.pem

    # Self-signed certs cause browsers to block Secure cookies even after
    # clicking through the cert warning — disable the Secure attribute so
    # login actually works. Mirrors install.sh and the Docker entrypoint.
    CONFIG="/opt/persea/config.toml"
    if ! grep -q 'secure_cookies' "$CONFIG" 2>/dev/null; then
        if grep -q '^\[tls\]' "$CONFIG" 2>/dev/null; then
            # Insert into the existing [tls] section — a second [tls] header
            # is invalid TOML ("duplicate key") and breaks config loading.
            sed -i '/^\[tls\]/a secure_cookies = false  # self-signed cert — browsers block Secure cookies' "$CONFIG"
        else
            {
                echo ""
                echo "[tls]"
                echo "secure_cookies = false  # self-signed cert — browsers block Secure cookies"
            } >> "$CONFIG"
        fi
        echo "Added secure_cookies = false to $CONFIG for the self-signed cert."
    fi
fi
chown -R persea:persea /opt/persea/tls

# Update shared library cache for the guacd libraries
/sbin/ldconfig

# ── SELinux: load the policy module and label ports/files ──
# selinuxenabled returns 0 only when SELinux is enforcing or permissive,
# so installs on SELinux-disabled hosts (or containers) skip this cleanly.
if selinuxenabled 2>/dev/null; then
    if semodule -i /usr/share/selinux/targeted/persea.pp 2>/dev/null; then
        echo "Loaded the persea SELinux policy module."
    else
        echo "WARNING: could not load the persea SELinux module — services may be blocked in enforcing mode." >&2
    fi
    semanage port -a -t persea_port_t -p tcp 443 2>/dev/null || true
    semanage port -a -t guacd_port_t -p tcp 4822 2>/dev/null || true
    restorecon -Rv /opt/persea \
        /usr/lib/systemd/system/persea.service \
        /usr/lib/systemd/system/persea-guacd.service >/dev/null 2>&1 || true
fi

# ── firewalld: open the web UI port (guacd is loopback-only, but the
# install convention opens both, mirroring the locked packaging notes) ──
if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
    firewall-cmd --permanent --add-port=443/tcp >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-port=4822/tcp >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
    echo "firewalld: opened 443/tcp and 4822/tcp."
fi

echo ""
echo "  persea installed. Next steps:"
echo "    sudo /opt/persea/bin/persea --config /opt/persea/config.toml add-admin --name admin"
echo "    sudo systemctl start persea    (starts both guacd + persea)"
echo ""

exit 0
