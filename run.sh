#!/bin/bash

if [ -r ./config.sh ]; then
  source ./config.sh
else
  source ./config-sample.sh
fi

for var in DB_NAME USER; do
  if [ -z "${!var}" ]; then
    echo "$var not set in config.sh, aborting" >&2
    exit 1
  fi
done

run_mysql() {
  if [ -n "$PASSWORD" ]; then
    mysql -u"$USER" -p"$PASSWORD" -D"$DB_NAME" "$@"
  else # Assume no password
    mysql -u"$USER" -D"$DB_NAME" "$@"
  fi
}

run() {
  local FILE="$1"
  run_mysql -Ns < "$FILE"
}

run_all() {
  local DIR="db_backup" file
  for file in "$DIR"/*; do
    :
  done
}
