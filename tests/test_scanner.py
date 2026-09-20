import os
import tempfile
from logsentinel.scanner import LogScanner

def test_empty_file():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    try:
        scanner = LogScanner(path)
        res = scanner.scan()
        assert res["total_lines"] == 0
        assert res["risk_score"] == 0
        print("Empty file test passed!")
    finally:
        os.unlink(path)

def test_malformed_and_mixed_logs():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    try:
        with open(path, 'w', encoding='utf-8') as f:
            f.write("Normal log line 1\n")
            f.write("Failed password for root from 127.0.0.1\n")
            f.write("ERROR: Database timeout exception\n")
            f.write("sudo: admin executed apt-get update\n")
            f.write("Normal log line 2\n")
            
        scanner = LogScanner(path)
        res = scanner.scan()
        assert res["total_lines"] == 5
        assert res["failed_password_count"] == 1
        assert res["sudo_anomaly_count"] == 1
        assert res["error_count"] == 1
        assert res["risk_score"] == 10
        print("Malformed and mixed logs test passed!")
    finally:
        os.unlink(path)

def test_nonexistent_file():
    scanner = LogScanner("/nonexistent/path/log.log")
    res = scanner.scan()
    assert "error" in res
    print("Nonexistent file test passed!")

if __name__ == "__main__":
    test_empty_file()
    test_malformed_and_mixed_logs()
    test_nonexistent_file()
    print("All logsentinel tests passed.")
