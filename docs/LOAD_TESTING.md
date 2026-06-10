# Load Testing

The platform v1 target is at least 10,000 active Windows endpoints across tenants.

`script/load_sim.py` simulates the agent API path:

```text
enrollment -> heartbeat -> telemetry ingest -> detection alerts
```

## Small smoke load

```bash
cd /opt/open-edr-mdr-agent
. .venv/bin/activate
open-edr-mdr-agent serve --host 127.0.0.1 --port 8770 --db /tmp/open-edr-mdr-load.sqlite3

scripts/load_sim.py --base http://127.0.0.1:8770 --agents 100 --events-per-agent 3 --workers 20
```

## Larger target runs

Start with staged load. Do not jump straight to 10k while SQLite is still the M0 store.

```bash
scripts/load_sim.py --base http://127.0.0.1:8770 --agents 500 --events-per-agent 3 --workers 50
scripts/load_sim.py --base http://127.0.0.1:8770 --agents 2000 --events-per-agent 3 --workers 100
scripts/load_sim.py --base http://127.0.0.1:8770 --agents 10000 --events-per-agent 1 --workers 200
```

## Notes

- SQLite is acceptable for the intranet vertical slice but not the final 10k production store.
- Use this simulator to validate API correctness and rough throughput before moving ingestion to a queue + OpenSearch/ClickHouse/PostgreSQL split.
- Current small validation run: 25 agents, 50 events, 25 alerts in ~0.7s on local host.
