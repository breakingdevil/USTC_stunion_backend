#!/bin/bash

# Load configuration
if [ -r ./config.sh ]; then
  source ./config.sh
else
  source ./config_sample.sh
fi

# Process default options
OUTPUT="${OUTPUT:-stunion.txt}"

# Process mandatory options
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

run_all() {
  local DIR="db_backup" file
  for file in "$DIR"/*.sql; do
    # Requires MariaDB 10.1.3
    run_mysql "CREATE OR REPLACE DATABASE $DB_NAME;"
    # Import dump
    run_mysql <"$file"
    # Create file header
    echo "Query results for \"${file}\":" >>"$OUTPUT"
    for query in queries/{user_count,user_type,wish_status,love_count}.sql; do
      echo "Query \"${query##*/}\""
      run_mysql <"$query" >>"$OUTPUT"
    done
  done
}

# Run whatever on the command line
CMD="${1:-run_all}"
shift
"$CMD" "$@"
