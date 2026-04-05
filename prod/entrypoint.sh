#!/bin/bash

set -eu

# Migration switch used during upgrades from old root-based images.
# When true, the entrypoint attempts to re-own mounted folders so the
# runtime user (cyberbro) can read/write SQLite and log files.
MIGRATE_OWNERSHIP_ON_START="${MIGRATE_OWNERSHIP_ON_START:-true}"

fix_path_ownership_if_needed() {
    target_path="$1"

    # Skip if the mount/path does not exist in this deployment mode.
    if [ ! -e "$target_path" ]; then
        return
    fi

    # Ownership migration requires root privileges.
    # If the container is forced to run as non-root, we do not fail here;
    # supervisord/gunicorn startup will reveal permission issues explicitly.
    if [ "$(id -u)" -ne 0 ]; then
        return
    fi

    # Allow operators to disable automatic migration when they manage
    # permissions externally (e.g., pre-provisioned volumes).
    if [ "$MIGRATE_OWNERSHIP_ON_START" != "true" ]; then
        return
    fi

    # Upgrade path: legacy containers may have created root-owned files in
    # bind mounts. Reassign ownership only when at least one item is not
    # already owned by cyberbro:cyberbro to avoid expensive no-op recursion.
    first_mismatch="$(find "$target_path" \( ! -user cyberbro -o ! -group cyberbro \) -print -quit)"
    if [ -z "$first_mismatch" ]; then
        return
    fi

    if ! chown -R cyberbro:cyberbro "$target_path"; then
        echo "[entrypoint] warning: unable to chown $target_path, continuing"
    fi
}

# Remove stale version cache after upgrades so update checks are refreshed.
if [ -f "data/version_cache.json" ]; then
    rm "data/version_cache.json"
fi

# Ensure mounted directories are writable by the app runtime user.
fix_path_ownership_if_needed "/app/data"
fix_path_ownership_if_needed "/var/log/cyberbro"

# Start supervisord; gunicorn itself runs as cyberbro from supervisord.conf.
exec /usr/bin/supervisord -c /app/prod/supervisord.conf
