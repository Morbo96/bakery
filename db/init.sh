#!/bin/sh
set -eu
pg_restore --exit-on-error --no-owner --no-privileges -U "$POSTGRES_USER" -d "$POSTGRES_DB" /backup/bakery.backup
