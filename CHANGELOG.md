# SOC Platform — Fixes Applied

This is the corrected codebase. Every item from the review is addressed below;
each fix is also marked inline in the code with a `# FIX:` / `<!-- FIX: -->` comment
so you can diff against your original files easily.

| # | Issue | Fix |
|---|-------|-----|
| 1 | `acknowledged_by`/`comments` columns existed but were never used | Added `acknowledge_alert()`, `add_comment()`, `update_status()` to `database.py` and wired them to new `/api/alerts/<id>/ack`, `/comment`, `/status` routes + an "Ack" button in the dashboard |
| 2 | Port-scan/connection trackers grew forever (memory leak) | Added `prune_trackers()` + a background `TrackerPruner` thread in `nids_engine.py` that drops idle entries every 120s |
| 3 | Each NIDS consumer thread had its own `DetectionEngine`, so a scanning IP split across threads could dodge thresholds | `DetectionEngine` is now instantiated once and shared across all consumer threads, guarded by a lock |
| 4 | No retry on `database is locked` under concurrent writers (NIDS + ML engine + future honeypot all write to the same SQLite file) | Added `busy_timeout` pragma + `_execute_with_retry()` with exponential backoff in `database.py` |
| 5 | `phase3_ingestion.py` ("ML Engine") was a no-op — never read auth.log, never called its own `_add_alert` | Rewritten to actually tail `/var/log/auth.log` (or `/var/log/secure`), parse failed SSH logins, track per-IP attempt windows, and raise real alerts |
| 6 | Flask dashboard had zero auth, `0.0.0.0` bind, hardcoded `SECRET_KEY`, wide-open CORS | Default bind is now `127.0.0.1` (override via `SOC_FLASK_HOST`), `SECRET_KEY` and a generated `X-API-Key` are persisted to `storage/.secret_key` / `.api_key` (or set via env), CORS is an explicit allow-list, and all `/api/*` routes require the API key |
| 7 | `background_refresh` spawned a new infinite loop per socket reconnect | Now started exactly once, guarded by a lock + flag |
| 8 | `daemon/launcher.py` ran NIDS via `sudo`, which conflicts with the documented `setcap` step and will hang waiting for a password under systemd | Removed `sudo`; rely on `setcap cap_net_raw,cap_net_admin=eip` as already documented in the deployment steps |
| 9 | Alert IDs were `hash(ip)+timestamp`, which collided on same-IP/same-second alerts and silently dropped the second insert | Switched to `uuid4`-based IDs in the shared `SOCDatabase.make_alert_id()` |
| 10 | NIDS and the dashboard each reimplemented their own SQLite layer with a duplicated INSERT statement | Both now import the single `ingestion/database.py::SOCDatabase` class — one schema, one write path |
| 11 | No log rotation — `nids_engine.log` / `ml_engine.log` grow unbounded | Switched to `RotatingFileHandler` (10MB × 5 backups, configurable in `settings.py`) |
| 12 | `cloud_filter.py`'s AWS/Azure ranges used coarse `/8`–`/10` blocks, causing false negatives across huge swaths of non-cloud IP space | Replaced with a smaller, more conservative built-in list (no `/8`s) and added support for loading the *official* AWS/Azure JSON ranges from `data/cloud_ranges.json` if you drop one in |
| 13 | No crash recovery for child processes started by the launcher | Added a watchdog thread that detects a dead child and restarts it (3s backoff) |
| 14 | `train_model.py` produces a `.pkl` model that's never loaded anywhere — "ML-Detected" alerts didn't actually come from this model | **Closed.** Added `ingestion/ml_inference.py` (loads the trained model/scaler/encoder and scores feature vectors) and `pipeline/flow_features.py` (builds a per-source-IP traffic profile and maps it onto the model's expected feature names). `nids_engine.py`'s `DetectionEngine` now runs both layers: rule-based checks first (port scan, connection flood), and if neither fires, a rate-limited ML check on that source IP's traffic profile. Every alert is tagged with a new `detection_method` column (`'rule'` or `'ml'`) so you can tell which layer caught what. |

## Hybrid detection (rule-based + ML) — what's covered

| Threat | Method | Where |
|---|---|---|
| Port scan | Rule (≥5 distinct ports from one IP within the window) | `nids_engine.py::DetectionEngine._check_port_scan` |
| Connection flood / DDoS-style | Rule (≥20 TCP connections from one IP within the window) | `nids_engine.py::DetectionEngine._check_connection_flood` |
| SSH brute-force | Rule (≥5 failed logins from one IP within 120s, parsed from auth.log) | `scripts/phase3_ingestion.py` |
| General traffic anomaly | ML (Random Forest scores a rolling per-IP traffic profile) | `ingestion/ml_inference.py` + `pipeline/flow_features.py`, invoked from `DetectionEngine._check_ml_anomaly` |

**Honest caveat on the ML layer:** the Random Forest is trained on CICIDS2017,
whose features come from a dedicated flow exporter (CICFlowMeter) with ~70-80
very specific bidirectional-flow statistics. Reconstructing all of those
exactly from raw `scapy` packets in real time is out of scope here.
`pipeline/flow_features.py` instead computes a handful of generic stats
(packet count, byte volume, duration, packet-size min/max/avg, unique
destination ports/IPs, rate) and fuzzy-matches them onto whatever feature
names `train_model.py` saved to `model/features.json`; anything it can't
confidently map is filled with `0.0`. Treat the ML layer as a second opinion
that complements the rule-based engine, not an exact reimplementation of the
CICIDS2017 pipeline. If you want tighter fidelity later, the proper fix is a
real flow-aggregation library (e.g. `dpkt`/`pyshark` based CICFlowMeter-style
exporter) feeding the same `MLAnomalyDetector.predict()` interface — the
interface itself won't need to change.

The ML layer fails soft: if `model/random_forest_model.pkl` doesn't exist
yet (you haven't run `scripts/train_model.py`), `MLAnomalyDetector.available`
is `False` and the engine logs a warning, then runs rule-based detection only.
No crash, no missing alerts from the rule-based side.


## Setup notes specific to these fixes

- On first run, `web/app.py` will print a generated API key to stdout / journal —
  save it if you want to call `/api/*` from outside the bundled dashboard page.
- The SSH brute-force monitor needs read access to `/var/log/auth.log` (or
  `/var/log/secure` on RHEL-likes). If running as a non-root systemd user,
  add that user to the `adm` group: `sudo usermod -aG adm project`.
- `pipeline/cloud_filter.py` ships a deliberately small built-in list now.
  For accurate coverage, fetch `https://ip-ranges.amazonaws.com/ip-ranges.json`
  and Microsoft's Azure ServiceTags JSON, reshape them into
  `{"AWS": [...], "Azure": [...], ...}`, and save as `data/cloud_ranges.json`.

## Dataset integration (2nd pass)

You provided `processed_dataset.csv` (15,171 rows: BENIGN, PortScan,
FTP-Patator, SSH-Patator). Profiling it found:

- `timestamp`, `source_ip`, `destination_ip`, `protocol`, `failed_logins`,
  `anomaly_score`, `threat_score` were all **constant/dead columns** (every
  row identical) — zero signal, dropped from the feature set.
- The real signal lives in `destination_port`, `duration`, `packet_count`,
  `byte_count`, `connection_rate`. No NaNs, no duplicate rows.
- `duration` is in **microseconds**; `connection_rate` is a derived rate
  (`packet_count / duration_µs * 1e6`) — both confirmed by checking the
  arithmetic against sample rows. This matters because the live
  `FlowTracker` in `pipeline/flow_features.py` computes duration in
  **seconds** — without converting, every live feature vector would have
  been off by 6 orders of magnitude on that column alone. Added explicit
  unit conversion (`duration_microseconds = duration_seconds * 1_000_000`)
  plus an exact-name feature map (`_EXACT_FEATURE_MAP` in
  `flow_features.py`) for this specific 5-column schema, checked before
  falling back to the generic CICIDS-style fuzzy matcher.
- Trained: **98.48% test accuracy** (12,136 train / 3,035 test, stratified
  split), all 4 classes ≥0.98 F1. Reproducible via `scripts/train_model.py`.

**Bug found and fixed during training:** `train_model.py` checked
`y.dtype == 'object'` to decide whether to `LabelEncode` the target column.
Modern pandas (2.x with the string backend) reports string columns as dtype
`str`, not `object` — so that check silently evaluated `False` and
`label_encoder.pkl` was never written, even though `threat_label` is a
string column. Rather than patch the dtype check, removed the encoder
dependency entirely: scikit-learn classifiers support string class labels
natively (`model.classes_` already holds them in `predict_proba`'s column
order), so `ml_inference.py` now reads classes straight from the model. One
less artifact to keep in sync, and it sidesteps the same dtype trap
resurfacing with some other pandas/sklearn version combination later.

**Known accuracy caveat:** the training data is per-flow (each row already
represents one fully-formed flow, e.g. one port-scan probe = one row with
`packet_count≈1`). The live `FlowTracker` aggregates *all* packets from a
source IP into one rolling window regardless of destination port, which is
the right behavior for the rule-based port-scan/flood checks but means the
live feature vector fed to the ML model won't look exactly like a single
training row during an active scan (it'll look like one flow with many
packets across many ports, rather than many single-packet flows). This is
why the rule-based layer is intentionally checked first — it still catches
port scans and connection floods directly — and the ML layer is the second
opinion for *everything else* it picks up a meaningful confident signal on.
If you want the ML layer itself to be the primary port-scan detector, the
fix would be tracking per-(src,dst_port) flows instead of per-src_ip, which
is a bigger restructuring than this pass.

## Not yet done (next step you mentioned)

Honeypot integration — `daemon/launcher.py` and `config/settings.py` now have
placeholders (`HONEYPOT_ENABLED`, `HONEYPOT_PORTS`) but no honeypot component
exists yet. When you build it, route its alerts through
`ingestion/database.py::SOCDatabase.add_alert()` like everything else,
tag `source_component: 'honeypot'`, and register it as a fourth entry in
`daemon/launcher.py`'s `COMPONENTS` dict so the watchdog supervises it too.
