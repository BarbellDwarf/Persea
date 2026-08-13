# persea RPM spec — Red Hat Enterprise Linux 10 (and compatible EL 10 distros).
#
# ONE RPM containing: persea (Rust binary), guacd (C daemon built in %build
# from the pinned fork tarball), persea.service + persea-guacd.service, a
# SELinux policy module, and a self-signed certificate bootstrap in %post.
# Everything lives under /opt/persea (mirrors the debian/ package layout).
#
# Repositories required to build:
#   - RHEL 10 AppStream (gcc, cargo, pango-devel, ...)
#   - RHEL 10 CodeReady Builder (freerdp-devel = FreeRDP 3 headers,
#     CUnit-devel)
#   - EPEL 10: libwebsockets-devel, libtelnet-devel, libvncserver-devel,
#     ffmpeg-free-devel (the ffmpeg-free library set; full ffmpeg is RPM
#     Fusion only and is not needed by guacd)
#
# SPICE is intentionally not built on EL 10: spice-client-glib is not
# packaged for RHEL 10 or EPEL 10. The guacd configure flags mirror the
# Ubuntu release build in .github/workflows/release.yml, which also omits
# SPICE.
#
# The source tarball persea-<version>.tar.gz is produced by the release
# workflow (git archive of the tagged commit); the version is passed to
# rpmbuild with --define "persea_version <version>".
#
# guacd is built with crates-network-free tooling (autotools), but the Rust
# build pulls crates from crates.io during %build. Offline vendoring is a
# follow-up.

%{!?persea_version:%global persea_version 0.0.0}
%global _prefix /opt/persea
# guacd's libraries carry an RPATH of /opt/persea/lib (the bundled libdir,
# outside the /usr/lib* tree that the check allows). The same layout ships in
# the Debian package; the RPATH is intentional and harmless here.
%global __brp_check_rpaths %{nil}
# Overriding _prefix drags _libdir along to /opt/persea/lib64; the FreeRDP
# plugin dir and its %files entry must point at the real system libdir.
%global _libdir /usr/lib64
# No debuginfo/debugsource subpackages: find-debuginfo mishandles the
# /opt/persea layout and its .debug files leak into the main package (fails
# the unpackaged-files check). The .deb build ships no separate debug
# package either.
%global debug_package %{nil}

Name:           persea
Version:        %{persea_version}
Release:        1%{?dist}
Summary:        Lightweight Rust replacement for Apache Guacamole client
License:        Apache-2.0
URL:            https://github.com/persea-grove/persea
Source0:        %{name}-%{persea_version}.tar.gz

# ── Build requirements ──────────────────────────────────────────────────
# Rust toolchain (RHEL 10 AppStream)
BuildRequires:  cargo
BuildRequires:  rust
# C toolchain for guacd
BuildRequires:  gcc
BuildRequires:  gcc-c++
BuildRequires:  make
BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  libtool
BuildRequires:  pkgconf-pkg-config
BuildRequires:  git
# guacd library deps — RHEL 10 AppStream / CRB
BuildRequires:  cairo-devel
BuildRequires:  libjpeg-turbo-devel
BuildRequires:  libpng-devel
BuildRequires:  libwebp-devel
BuildRequires:  libssh2-devel
BuildRequires:  openssl-devel
BuildRequires:  pango-devel
BuildRequires:  pulseaudio-libs-devel
BuildRequires:  libuuid-devel
BuildRequires:  freerdp-devel
BuildRequires:  CUnit-devel
# guacd library deps — EPEL 10
BuildRequires:  libvncserver-devel
BuildRequires:  libtelnet-devel
BuildRequires:  libwebsockets-devel
BuildRequires:  ffmpeg-free-devel
# SELinux policy module build (the devel Makefile + semodule_package)
BuildRequires:  selinux-policy-devel
BuildRequires:  checkpolicy
# systemd scriptlet macros (systemd-rpm-macros)
BuildRequires:  systemd-rpm-macros

# ── Runtime requirements ────────────────────────────────────────────────
# RHEL 10 AppStream
Requires:       cairo
Requires:       libjpeg-turbo
Requires:       libpng
Requires:       libwebp
Requires:       libssh2
Requires:       openssl-libs
Requires:       pango
Requires:       pulseaudio-libs
Requires:       freerdp-libs
Requires:       ca-certificates
# EPEL 10
Requires:       libvncserver
Requires:       libtelnet
Requires:       libwebsockets
Requires:       ffmpeg-free
# SELinux module install (%post loads the policy; semanage relabels ports)
Requires:       policycoreutils
Requires:       policycoreutils-python-utils
Requires:       selinux-policy-targeted

# Optional features (installed by default with dnf unless weak deps are off)
Recommends:     tigervnc-server
Recommends:     chromium
Recommends:     xorg-x11-utils
Recommends:     cryptsetup
Recommends:     firewalld

%description
persea is a lightweight Rust replacement for the Apache Guacamole Java
webapp. It proxies the Guacamole protocol over WebSockets between web
browsers and guacd (the C daemon from guacamole-server). Supports SSH,
VNC, RDP, Proxmox, VMware, and web browser sessions (headless Chromium
on Xvnc). This package bundles both persea and guacd.

%prep
%autosetup -n persea-%{persea_version}

# RHEL 10's cargo defaults release builds to thin LTO + strip. Thin LTO on
# the final link (this crate graph includes aws-lc and the sqlite3
# amalgamation) needs several GB of RAM and has crashed builders; the
# Ubuntu release build uses the plain cargo defaults (no LTO), so mirror
# that here for parity and build reliability.
mkdir -p .cargo
cat > .cargo/config.toml <<'EOF'
[profile.release]
lto = false
EOF

%build
# RHEL 10's rpmbuild defaults enable gcc LTO in CFLAGS (-flto=auto). The
# final Rust link then LTOs the C objects (aws-lc, the sqlite3 amalgamation)
# in a single gcc process, which has OOM-crashed builders. Build without LTO
# to match the Ubuntu release build and keep peak memory sane.
export CFLAGS="${CFLAGS/-flto=auto/}"
export CXXFLAGS="${CXXFLAGS/-flto=auto/}"
export FFLAGS="${FFLAGS/-flto=auto/}"

# ── persea (Rust) — pulls crates from crates.io (offline vendoring: follow-up)
cargo build --release

# ── guacd (C) — pinned fork tarball, same repo/commit as the Ubuntu build ──
git clone --depth 1 --branch persea-1.6.1-freerdp3 \
    https://github.com/persea-grove/persea-guacamole-server.git guacamole-server
git -C guacamole-server checkout d9218fe1
( cd guacamole-server && autoreconf -fi )
mkdir guacd-build
cd guacd-build
../guacamole-server/configure \
    --prefix=%{_prefix} \
    --with-ssh \
    --with-vnc \
    --with-rdp \
    --without-telnet \
    --without-kubernetes \
    --disable-guacenc \
    --disable-guaclog \
    --disable-static
make %{?_smp_mflags}
cd ..

# ── SELinux policy module ──
cp rpm/selinux/*.te rpm/selinux/*.fc .
make -f /usr/share/selinux/devel/Makefile persea.pp

%install
rm -rf %{buildroot}

# Directory structure
install -d %{buildroot}%{_prefix}/bin
install -d %{buildroot}%{_prefix}/sbin
install -d %{buildroot}%{_prefix}/lib
install -d %{buildroot}%{_prefix}/static
install -d %{buildroot}%{_prefix}/data
install -d %{buildroot}%{_prefix}/recordings
install -d %{buildroot}%{_prefix}/tls
install -d %{buildroot}%{_unitdir}
install -d %{buildroot}%{_sysconfdir}/ld.so.conf.d
install -d %{buildroot}%{_libdir}/freerdp3
install -d %{buildroot}%{_libexecdir}/persea
install -d %{buildroot}/usr/share/selinux/targeted

# persea binary
install -m 755 target/release/persea %{buildroot}%{_prefix}/bin/persea

# Drive setup helper script
install -m 755 scripts/drive-setup.sh %{buildroot}%{_prefix}/bin/drive-setup.sh

# guacd binary and libraries
make -C guacd-build DESTDIR=%{buildroot} install

# make install also ships dev headers, man pages, and the guacclip helper;
# this package deliberately ships none of them (guacenc/guaclog are disabled
# at configure time, guacclip only makes sense with them, and the man pages
# describe the old guacd.conf layout, not the packaged config.toml).
rm -rf %{buildroot}%{_prefix}/include
rm -rf %{buildroot}%{_prefix}/share/man
rm -f %{buildroot}%{_prefix}/bin/guacclip

# FreeRDP 3 plugins (RDPDR/RDPSND channels: drive redirection, audio,
# printing). guacd's make install already places them next to the system
# FreeRDP libraries (pkg-config freerdp plugin dir) so freerdp finds them at
# runtime; the copy below is a fallback if a future guacd version installs
# them under the guacd prefix instead.
cp -a %{buildroot}%{_prefix}/lib/freerdp3/*.so* %{buildroot}%{_libdir}/freerdp3/ 2>/dev/null || true
rm -rf %{buildroot}%{_prefix}/lib/freerdp3

# Static web assets
cp -r static/* %{buildroot}%{_prefix}/static/

# Default config (EL 10 default: HTTPS on 443)
install -m 644 rpm/config.toml.default %{buildroot}%{_prefix}/config.toml

# ldconfig drop-in so guacd can find its libs
echo "%{_prefix}/lib" > %{buildroot}%{_sysconfdir}/ld.so.conf.d/persea.conf

# Systemd units
install -m 644 rpm/persea.service %{buildroot}%{_unitdir}/persea.service
install -m 644 rpm/persea-guacd.service %{buildroot}%{_unitdir}/persea-guacd.service

# SELinux policy module + install/remove scriptlets
install -m 644 persea.pp %{buildroot}/usr/share/selinux/targeted/persea.pp
install -m 755 rpm/scripts/pre.sh %{buildroot}%{_libexecdir}/persea/pre.sh
install -m 755 rpm/scripts/post.sh %{buildroot}%{_libexecdir}/persea/post.sh
install -m 755 rpm/scripts/postun.sh %{buildroot}%{_libexecdir}/persea/postun.sh

%pre
# Mirrors debian/preinst (Chromium's crashpad needs a real home directory).
if ! getent passwd persea >/dev/null 2>&1; then
    useradd -r -m -d /home/persea -s /sbin/nologin -c "persea service account" persea
fi

%post
%{_libexecdir}/persea/post.sh || exit $?
%systemd_post persea.service persea-guacd.service

%preun
%systemd_preun persea.service persea-guacd.service

%postun
if [ "$1" -eq 0 ]; then
    # Mirrors debian/postrm (purge): drop SELinux/firewalld changes, data,
    # ld.so.conf entry, and the service account (runs after files removed).
    if selinuxenabled 2>/dev/null; then
        semodule -r persea 2>/dev/null || true
        semanage port -d -t persea_port_t -p tcp 443 2>/dev/null || true
        semanage port -d -t guacd_port_t -p tcp 4822 2>/dev/null || true
    fi
    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
        firewall-cmd --permanent --remove-port=443/tcp >/dev/null 2>&1 || true
        firewall-cmd --permanent --remove-port=4822/tcp >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
    fi
    rm -rf /opt/persea
    rm -f /etc/ld.so.conf.d/persea.conf
    /sbin/ldconfig
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
%config(noreplace) %attr(0640,persea,persea) %{_prefix}/config.toml
%dir %attr(0750,persea,persea) %{_prefix}/data
%dir %attr(0750,persea,persea) %{_prefix}/recordings
%dir %attr(0750,persea,persea) %{_prefix}/tls
%{_unitdir}/persea.service
%{_unitdir}/persea-guacd.service
%{_sysconfdir}/ld.so.conf.d/persea.conf
%{_libexecdir}/persea/pre.sh
%{_libexecdir}/persea/post.sh
%{_libexecdir}/persea/postun.sh
/usr/share/selinux/targeted/persea.pp
