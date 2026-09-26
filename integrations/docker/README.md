# Docker Engine events -> SentinelForge

Docker's event stream (container start, exec, …) isn't a log file, so there's no shipper for it. The library CLI
streams it instead:

```bash
pip install sentinelforge-detect
export SENTINELFORGE_API_KEY=...
docker events --filter type=container --format '{{json .}}' \
  | sentinelforge forward --url https://sentinelforge.example.internal --source docker --host "$(hostname)"
```

Each event is POSTed as it arrives (`--batch 1`, the default). Failed sends are retried 3 times.

To run it permanently, install [`sentinelforge-docker-events.service`](sentinelforge-docker-events.service) as a systemd unit:

```bash
sudo cp sentinelforge-docker-events.service /etc/systemd/system/
sudo systemctl edit sentinelforge-docker-events   # set SENTINELFORGE_URL / SENTINELFORGE_API_KEY
sudo systemctl enable --now sentinelforge-docker-events
```

Docker events carry the image and container name but not published ports or `--privileged`. Rules that need
those fields (DET-DOCKER-002/003) only fire when the record includes them, for example from `docker inspect`
enrichment or a runtime sensor. DET-DOCKER-001 (unapproved image) works from the event stream alone.
