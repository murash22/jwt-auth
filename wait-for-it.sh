#!/bin/sh
set -e

shift
cmd="$@"
export $(grep -v '^#' .env | xargs)

until PGPASSWORD=$POSTGRES_PASSWORD psql -h "$DB_HOST" -p "$DB_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c '\q' > /dev/null 2>&1; do
  >&2 echo "db is not available yet"
  sleep 1
done

>&2 echo "db is up, starting app..."
exec $cmd