# pi-model-radar

A lightweight, stdlib-only Python 3 tool for discovering, caching, diffing, and health-probing Pi models.

## Usage

```bash
# Scan available models via `pi --list-models` and cache report
python scripts/radar.py scan

# Show cached report status (age, provider counts, default, diff, probes)
python scripts/radar.py status

# Probe model responsiveness via `pi -p ...` (refuses unknown IDs)
python scripts/radar.py probe --model <provider/model> [--timeout 120]

# Recommend verified models (default first, then context desc)
python scripts/radar.py recommend
```

## Configuration

- Report path defaults to `~/.pi/agent/pi-model-radar.json`.
- Settings path defaults to `~/.pi/agent/settings.json`.
- Override via environment variables:
  - `PI_RADAR_REPORT`: custom path for report JSON
  - `PI_SETTINGS_PATH`: custom path for Pi settings JSON

## Running Tests

```bash
python tests/test_radar.py
```
