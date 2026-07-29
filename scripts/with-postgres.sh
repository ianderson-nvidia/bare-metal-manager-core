#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Run a command with an ephemeral PostgreSQL instance.
#
# Starts a throwaway cluster on a unix socket, creates the `root` superuser and
# `root` database, exports DATABASE_URL, runs the given command, then tears the
# cluster down regardless of outcome.
#
#   ./scripts/with-postgres.sh cargo make test-release-container-services
#
# This replaces the postgres that dev/docker/Dockerfile.build-container-x86_64
# baked in and that CI started with `/etc/init.d/postgresql start`. The
# resulting DATABASE_URL has the same shape CI used, so nothing downstream
# needs to change:
#
#   postgresql://root@%2Fpath%2Fto%2Fsocket/root
#
# Requires initdb/pg_ctl/createdb on PATH — `nix develop` provides them via
# postgresql_15 in the devShell.

set -euo pipefail

if [ $# -eq 0 ]; then
	echo "usage: $0 <command> [args...]" >&2
	exit 2
fi

for bin in initdb pg_ctl createdb; do
	command -v "$bin" >/dev/null 2>&1 || {
		echo "error: $bin not found on PATH." >&2
		echo "Run inside the dev shell:  nix develop -c $0 $*" >&2
		exit 1
	}
done

# The cluster lives outside the repo. Socket paths are capped at ~107 bytes by
# the kernel, so this must stay short — a project-local dir under a deep
# checkout path can exceed the limit.
WORKDIR="$(mktemp -d -t carbide-pg-XXXXXX)"
PGDATA="${WORKDIR}/data"
PGSOCK="${WORKDIR}/sock"

cleanup() {
	rc=$?
	if [ -d "${PGDATA}" ]; then
		# -m immediate: this is a disposable cluster, no need for a clean
		# checkpoint. Silence failures so teardown never masks the real code.
		pg_ctl -D "${PGDATA}" -m immediate stop >/dev/null 2>&1 || true
	fi
	rm -rf "${WORKDIR}"
	exit "${rc}"
}
trap cleanup EXIT

mkdir -p "${PGSOCK}"

# trust auth is safe here: the cluster listens only on a socket inside a
# mkstemp-created directory, and is destroyed when this script exits.
initdb --username=root --auth=trust -D "${PGDATA}" >/dev/null

# -h '' disables TCP entirely, so concurrent runs (and CI runners with a real
# postgres already on 5432) cannot collide.
pg_ctl -D "${PGDATA}" -o "-k ${PGSOCK} -h ''" -w start >/dev/null

createdb -h "${PGSOCK}" -U root root

# libpq wants the socket *directory* percent-encoded in the URL host position.
ENCODED_SOCK="${PGSOCK//\//%2F}"
export DATABASE_URL="postgresql://root@${ENCODED_SOCK}/root"

echo "postgres ready: DATABASE_URL=${DATABASE_URL}"

"$@"
