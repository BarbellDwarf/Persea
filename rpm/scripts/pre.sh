#!/bin/sh
# persea RPM %pre scriptlet — create the service account.
# Mirrors debian/preinst (Chromium's crashpad needs a real home directory).
set -e

if ! getent passwd persea >/dev/null 2>&1; then
    useradd -r -m -d /home/persea -s /sbin/nologin -c "persea service account" persea
fi

exit 0
