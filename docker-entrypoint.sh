#!/bin/sh
set -e

# Volume mounts arrive root-owned. Railway bind-mounts its volumes without
# inheriting the image directory's ownership, so a container that starts as
# an unprivileged user cannot write to its own data directory. Fix ownership
# first, then drop to that user before exec'ing the server.
if [ "$(id -u)" = "0" ]; then
    chown -R 10001:10001 /var/lib/brolly
    exec setpriv --reuid=10001 --regid=10001 --clear-groups "$@"
fi

exec "$@"
