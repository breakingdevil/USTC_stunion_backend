#!/bin/bash

source ./config.sh

run_mysql() {
  if [ -n "$PASSWORD" ]; then
    mysql -u"$USER" -p"$PASSWORD" -D "$DB_NAME" "$@"
  else # Assume no password
    mysql -u"$USER" -D "$DB_NAME" "$@"
  fi
}

run() {
}
