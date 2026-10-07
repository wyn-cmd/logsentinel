import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from logsentinel.scanner import LogScanner


@pytest.fixture
def temp_log_file():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    yield path
    if os.path.exists(path):
        os.unlink(path)


def test_empty_file(temp_log_file):
    scanner = LogScanner(temp_log_file)
    res = scanner.scan()
    assert res["total_lines"] == 0
    assert res["risk_score"] == 0


def test_malformed_and_mixed_logs(temp_log_file):
    with open(temp_log_file, "w", encoding="utf-8") as f:
        f.write("Normal log line 1\n")
        f.write("Failed password for root from 127.0.0.1\n")
        f.write("ERROR: Database timeout exception\n")
        f.write("sudo: admin executed apt-get update\n")
        f.write("Normal log line 2\n")
        
    scanner = LogScanner(temp_log_file)
    res = scanner.scan()
    assert res["total_lines"] == 5
    assert res["failed_password_count"] == 1
    assert res["sudo_anomaly_count"] == 1
    assert res["error_count"] == 1
    assert res["risk_score"] == 10


def test_nonexistent_file():
    scanner = LogScanner("/nonexistent/path/log.log")
    res = scanner.scan()
    assert "error" in res


def test_max_anomalies_limit(temp_log_file):
    with open(temp_log_file, "w", encoding="utf-8") as f:
        for _ in range(600):
            f.write("Failed password for root\n")
            
    scanner = LogScanner(temp_log_file)
    res = scanner.scan()
    assert len(res["anomalies"]) == scanner.MAX_ANOMALIES
    assert res["failed_password_count"] == 600


if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))