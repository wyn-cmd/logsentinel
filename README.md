# LogSentinel

LogSentinel is a small, zero-dependency local command line tool that scans system logs, authentication logs, and application output for suspicious anomalies, brute-force patterns, and error spikes. It is plain Python with a test suite, and it runs straight from the terminal.

## Features

- **Fast scanning**: Scans tens of thousands of log lines in well under a second with zero external dependencies.
- **Risk scoring**: Adds up a threat score from detected authentication failures, sudo privilege events, and error spikes.
- **JSON output**: Writes the anomaly list as JSON (`--json`) so other scripts can read it.
- **Tested**: Unit tests cover normal logs, a 50,000 line stress run, and missing files. They use pytest, so run `pip install pytest` once and then `python3 -m pytest tests` (or `python3 tests/test_scanner.py`, which calls the same runner).

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

## How scoring works

Each non-empty line is matched against three case-insensitive patterns, and every pattern that hits adds its weight to the risk score: authentication failures (`failed password`, `authentication failure`, `invalid user`) add 5, sudo activity (`sudo`, `su:`) adds 2, and error indicators (`error`, `critical`, `fatal`, `exception`) add 3. The patterns are checked independently, so a single line such as `sudo: authentication failure for root` scores 7 and increments both counters.

The counters always reflect every match in the file, but only the first 500 anomalies are kept in the `anomalies` list to bound memory on large inputs, and the plain text output prints just the first 50 with their line numbers. Use `--json` when you need the full stored list.
