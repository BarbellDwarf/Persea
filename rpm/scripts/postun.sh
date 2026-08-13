#!/bin/sh
# persea RPM %postun scriptlet — runs only on full uninstall ($1 = 0).
# Mirrors debian/postrm (purge) + removes the SELinux/firewalld changes.
set -e

# SELinux: drop the module and the custom port labels
if selinuxenabled 2>/dev/null; then
    semodule -r persea 2>/dev/null || true
    semanage port -d -t persea_port_t -p tcp 443 2>/dev/null || true
    semanage port -d -t guacd_port_t -p tcp 4822 2>/dev/null || true
fi

# firewalld: close the ports we opened
if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
    firewall-cmd --permanent --remove-port=443/tcp >/dev/null 2>&1 || true
    firewall-cmd --permanent --remove-port=4822/tcp >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
fi

# Runtime data and the service account
rm -rf /opt/persea
rm -f /etc/ld.so.conf.d/persea.conf
/sbin/ldconfig
userdel -r persea 2>/dev/null || true

exit 0
