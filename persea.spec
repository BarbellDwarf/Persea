# RPM spec for persea — lightweight Rust replacement for Apache Guacamole.
#
# This spec expects pre-built binaries (build-rpm.sh does compilation before
# rpmbuild runs). The _builddir macro is pointed at the repo checkout so
# install phase can find everything in place.
#
# Target: Rocky Linux 9 / RHEL 9 / AlmaLinux 9
# Requires EPEL for: ffmpeg-libs, libtelnet, libwebsockets, chromium

%global _prefix /opt/persea

Name:           persea
Version:        %{_version}
Release:        1%{?dist}
Summary:        Lightweight Rust replacement for Apache Guacamole client
License:        Apache-2.0
URL:            https://github.com/persea-grove/persea

BuildRequires:  systemd-rpm-macros

Requires:       cairo
Requires:       libjpeg-turbo
Requires:       libpng
Requires:       libwebp
Requires:       libssh2
Requires:       openssl-libs
Requires:       libvncserver
Requires:       pango
Requires:       pulseaudio-libs
Requires:       ffmpeg-libs
Requires:       libtelnet
Requires:       libwebsockets
Requires:       freerdp-libs
Requires:       ca-certificates

Recommends:     tigervnc-server
Recommends:     chromium
Recommends:     xorg-x11-utils
Recommends:     cryptsetup

%description
persea is a lightweight Rust replacement for the Apache Guacamole Java
webapp. It proxies the Guacamole protocol over WebSockets between web
browsers and guacd (the C daemon from guacamole-server). Supports SSH,
VNC, RDP, and web browser sessions (headless Chromium on Xvnc).

# Nothing to unpack or compile — build-rpm.sh handles everything.
%prep

%build

%install
rm -rf %{buildroot}

# Directory structure
install -d %{buildroot}%{_prefix}/bin
install -d %{buildroot}%{_prefix}/sbin
install -d %{buildroot}%{_prefix}/lib
install -d %{buildroot}%{_prefix}/static
install -d %{buildroot}%{_prefix}/static/guac
install -d %{buildroot}%{_prefix}/data
install -d %{buildroot}%{_prefix}/recordings
install -d %{buildroot}%{_prefix}/tls
install -d %{buildroot}%{_unitdir}
install -d %{buildroot}%{_sysconfdir}/ld.so.conf.d

# persea binary
install -m 755 target/release/persea %{buildroot}%{_prefix}/bin/persea

# Drive setup helper script
install -m 755 scripts/drive-setup.sh %{buildroot}%{_prefix}/bin/drive-setup.sh

# guacd binary and libraries from staging
install -m 755 rpm/staging%{_prefix}/sbin/guacd %{buildroot}%{_prefix}/sbin/guacd
cp -a rpm/staging%{_prefix}/lib/*.so* %{buildroot}%{_prefix}/lib/

# FreeRDP plugin for RDPDR/RDPSND channels (drive redirection, audio, printing)
install -d %{buildroot}%{_libdir}/freerdp3
cp -a rpm/staging%{_libdir}/freerdp3/*.so* %{buildroot}%{_libdir}/freerdp3/ 2>/dev/null || true

# Static web assets
cp -r static/* %{buildroot}%{_prefix}/static/

# Default config — reuse the debian default (no duplication)
install -m 644 debian/config.toml.default %{buildroot}%{_prefix}/config.toml

# Systemd units — reuse the debian service files (no duplication)
install -m 644 debian/persea.service %{buildroot}%{_unitdir}/persea.service
install -m 644 debian/persea-guacd.service %{buildroot}%{_unitdir}/persea-guacd.service

# ldconfig drop-in so guacd can find its libs
echo "%{_prefix}/lib" > %{buildroot}%{_sysconfdir}/ld.so.conf.d/persea.conf

%pre
# Create persea system user with a real home directory (Chromium needs it)
if ! getent passwd persea >/dev/null 2>&1; then
    useradd -r -m -d /home/persea -s /sbin/nologin -c "persea service account" persea
fi

%post
chown -R persea:persea %{_prefix}/data %{_prefix}/recordings
# Generate self-signed TLS certificate if none exists
if [ ! -f %{_prefix}/tls/cert.pem ] || [ ! -f %{_prefix}/tls/key.pem ]; then
    CERT_HOSTNAME=$(hostname -f 2>/dev/null || hostname)
    echo "Generating self-signed TLS certificate for ${CERT_HOSTNAME}..."
    %{_prefix}/bin/persea generate-cert \
        --hostname "$CERT_HOSTNAME" \
        --out-dir %{_prefix}/tls
    chmod 600 %{_prefix}/tls/key.pem
    chmod 644 %{_prefix}/tls/cert.pem
fi
chown -R persea:persea %{_prefix}/tls
/sbin/ldconfig
%systemd_post persea.service persea-guacd.service
echo ""
echo "  To set up encrypted file transfer (LUKS drive), run:"
echo "    sudo %{_prefix}/bin/drive-setup.sh"
echo ""

%preun
%systemd_preun persea.service persea-guacd.service

%postun
/sbin/ldconfig
if [ $1 -eq 0 ]; then
    # Full uninstall — clean up
    rm -rf %{_prefix}
    userdel -r persea 2>/dev/null || true
fi
%systemd_postun_with_restart persea.service persea-guacd.service

%files
%license debian/copyright
%dir %{_prefix}
%{_prefix}/bin/persea
%{_prefix}/bin/drive-setup.sh
%{_prefix}/sbin/guacd
%{_prefix}/lib/*.so*
%{_libdir}/freerdp3/
%{_prefix}/static/
%config(noreplace) %{_prefix}/config.toml
%dir %attr(0750,persea,persea) %{_prefix}/data
%dir %attr(0750,persea,persea) %{_prefix}/recordings
%dir %attr(0750,persea,persea) %{_prefix}/tls
%{_unitdir}/persea.service
%{_unitdir}/persea-guacd.service
%{_sysconfdir}/ld.so.conf.d/persea.conf
