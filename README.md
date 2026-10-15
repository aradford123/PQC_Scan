# PQC_Scan

Track post-quantum (PQC) TLS adoption across a list of hosts over time.

`tester.py` connects to each target with `openssl s_client` and records the negotiated
protocol, cipher suite, signature type and key-exchange group. Each run saves a dated
snapshot. `analyse_pqc.py` loads all snapshots and reports how adoption of hybrid PQC
key exchange (`X25519MLKEM768`) has changed, either as console output and charts or as
a self-contained HTML report.

## Example report

![PQC TLS readiness report](docs/report_snapshot.png)

The latest scan (14 Oct 2026) shows **56.8% of reachable hosts (133 of 234)** negotiating
hybrid ML-KEM key exchange, up from 23.5% in the first scan on 1 Oct 2025. The jump
happened between the early-August and late-August 2026 scans. Below the charts, the full
report also lists the hosts that gained or lost PQC since the previous scan, plus a
per-host register (status, group, TLS version, cipher, and when PQC was first seen).

Open [`reports/pqc_report.html`](reports/pqc_report.html) in a browser to see the whole
report.

## Requirements

- Python 3.9+ with `pandas` and `matplotlib`
- `openssl` on your `PATH`. To negotiate `X25519MLKEM768` it must be OpenSSL 3.5+ (or
  a build with PQC support). An older client will report every host as classical.

```bash
pip install pandas matplotlib
openssl version
```

## Usage

### 1. Define targets

Targets live in `data/targets.py` as a list of `(host, port)` tuples:

```python
targets = [
    ("pq.cloudflareresearch.com", 443),
    ("www.google.com", 443),
]
```

`data/small-targets.py` and `data/targets-100.py` are alternative lists. To use one,
copy it over `data/targets.py` (or change the import in `tester.py`).

### 2. Run a scan

```bash
python tester.py
```

This writes `data/YYYY-MM-DD-tls_pqc_results.pkl` using today's date. Run it regularly
(say weekly) to build up a time series. Each host has a 15s timeout, and a host that
fails is recorded with an `Error` and counted as unreachable.

### 3. Generate the HTML report

```bash
python analyse_pqc.py --html reports/pqc_report.html
```

This loads every `*-tls_pqc_results.pkl` in `data/`, prints the summaries to the
console and writes a single HTML file. The file loads only Google Fonts from the
network, so it can be opened locally or shared as is.

To show interactive matplotlib charts instead (AES family, TLS group and hybrid PQC
adoption), leave out `--html`:

```bash
python analyse_pqc.py
```

Options:

| Flag | Default | Description |
| --- | --- | --- |
| `--data-dir` | `data` | Directory containing snapshot files |
| `--pattern` | `*-tls_pqc_results.pkl` | Glob for snapshot files |
| `--html PATH` | _(none)_ | Write the HTML report to `PATH` instead of showing charts |
| `--plot-dir` | `plots` | Chart output directory (saving is currently disabled, so charts are only displayed) |

### Inspect a single snapshot

```bash
python read_data.py data/2026-10-14-tls_pqc_results.pkl
```

This prints every reachable host with a simple quantum-readiness score (`QScore`) and a
status (`Pure PQC`, `Hybrid PQC`, `Classical`).

## Notes

- Percentages in the HTML report are of **reachable** hosts. The console summary from
  `analyse_pqc.py` divides by **all** targets, so its figures are slightly lower (for
  example, 55.0% vs 56.8% for the latest scan).
- A host counts as hybrid PQC when the negotiated group contains `X25519MLKEM768`.
  Results show what a default OpenSSL client negotiates, not every group a server
  supports.
