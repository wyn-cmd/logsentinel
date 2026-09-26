# LogSentinel

LogSentinel is a small, zero-dependency local command line tool that scans system logs, authentication logs, and application output for suspicious anomalies, brute-force patterns, and error spikes. It is plain Python with a test suite, and it runs straight from the terminal.

## Features

- **Fast scanning**: Scans tens of thousands of log lines in well under a second with zero external dependencies.
- **Risk scoring**: Adds up a threat score from detected authentication failures, sudo privilege events, and error spikes.
- **JSON output**: Writes the anomaly list as JSON (`--json`) so other scripts can read it.
- **Tested**: Unit tests cover normal logs, a 50,000 line stress run, and missing files. Run directly with `python3 tests/test_scanner.py`, no install step required.

## Installation

Install locally in editable mode using pip or uv:

```bash
pip install -e .
```

## Usage

Run logsentinel against any log file to analyze anomalies and compute risk scores:

```bash
logsentinel scan /var/log/auth.log
```

Export structured JSON results for automated workflows:

```bash
logsentinel scan --json /var/log/auth.log
```
