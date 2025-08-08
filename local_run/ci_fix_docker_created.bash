#!/bin/bash

echo Starting the stuck docker murderer...

# Set the age threshold to 4 minutes (240 seconds)
age_threshold=240

parse_date() {
    local date_string="$1"
    awk -v date="$date_string" '
    BEGIN {
        split(date, a, " ");
        gsub(/"/, "", a[3]); # Remove quotes from time
        gsub(/,/, "", a[3]); # Remove comma from time
        "date +%s -d \"" a[1] " " a[2] " " a[3] "\"" | getline timestamp;
        print timestamp;
    }'
}

check_for_bad() {
    docker ps -a --format json | jq --slurp '.[] | select(.State == "created") | "\(.ID) \(.CreatedAt)"' | while read -r id created_at
    do
      id="$(echo $id | tr -d '"')"
      created_seconds=$(parse_date "$created_at")
      current_seconds=$(date +%s)
      age_seconds=$((current_seconds - created_seconds))
      echo "Container $id has been stuck in created state for $age_seconds seconds..."
      #if [ $age_seconds -gt $age_threshold ]; then
      #  echo "Container $id has been stuck for longer than 4 minutes. Removing..."
      #  set -x
      #  docker rm -f "$id"
      #  set +x
      #  if [ $? -eq 0 ]; then
      #    echo "Container $id successfully MURDERED."
      #  else
      #    echo "Failed to remove container $id."
      #  fi
      fi
    done
}

while true; do
    check_for_bad
    sleep 60
done