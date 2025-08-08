# Telemetry Services

For every run, the services will spin up both the influxdb (the event log database) and telegraf (a system info collection service)

## Where do I get a telemetry.tar.gz

Download a zipped telemetry database from either the run summary or [https://ci.internal.artiphishell.com](https://ci.internal.artiphishell.com/) by clicking on one of the cards and selecting `telemetry.tar.gz` from the top right.

## Usage
After downloading an instance, navigate to `artiphishell/services` and run:
```bash
./start_grafana_from_backup.sh telemetry.tar.gz
```

This will bring up two containers `telemetry_db` (The influxdb) and `grafana` (the dashboard).

### Influxdb
If for whatever reason you want to poke around in the influxdb instance, go to `localhost:8086` and login with the credentials `shellphish:shellphish`.

### Grafana
This is where you'll want to be 99% of the time, go to `localhost:3000` and login with the credentials `admin:admin` (you can skip where it asks to set a new password).

On the lefthand side is a hamburger menu, go to -> Dashboards -> CRS Dashboard. \
By default the dashboard will be set to the current time, and auto-refresh every 10s. \
This will most-likely cause much of the data to be undisplayable. 

To the left of the date picker and refresh dropdown (which you can set to off) are the `CRS Run` and `Fuzzing` buttons.

The `CRS Run` button will re-load this same dashboard but in the time-range of the actual run. \
> [!WARNING]  
> Sometimes you will need to adjust the timeline with the time picker as there is too much data to load for entire runs.

The `Fuzzing` button will take you to the AFL++ dashboard with a button in a similar location to take you back.

## Live Runs
If you're feeling confident, you can even load the dashboard for a live run, however, this means that you will need access to the runners. \
You can set the date picker ranges to values such as `now` or `now-5m` and leave the dashboard auto update set to around `30s` to get a continual live feed.
``` bash
cd artiphishell/services/grafana
docker compose down -v
docker compose up -d
ssh -L 8086:localhost:8086 LIVE@RUNNER
```

This will forward 8086 which is the port of the influxdb on the runner to your localhost which the grafana dashboard should then have access to.