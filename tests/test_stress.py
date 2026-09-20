import os
import tempfile
import time
from logsentinel.scanner import LogScanner

def test_large_log_stress():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    try:
        # Write 50,000 log lines
        print("Writing 50,000 test log lines for stress testing...")
        start_time = time.time()
        with open(path, 'w', encoding='utf-8') as f:
            for i in range(50000):
                if i % 1000 == 0:
                    f.write(f"Jan 1 00:00:00 server sshd[1]: Failed password for invalid user admin from 192.168.1.{i%255}\n")
                elif i % 500 == 0:
                    f.write(f"Jan 1 00:00:00 server kernel: [ 0.00] Critical hardware error\n")
                else:
                    f.write(f"Jan 1 00:00:00 server systemd[1]: Started session {i} of user.\n")
        
        write_duration = time.time() - start_time
        print(f"Write completed in {write_duration:.2f} seconds.")
        
        # Scan large file
        print("Scanning large log file...")
        scan_start = time.time()
        scanner = LogScanner(path)
        res = scanner.scan()
        scan_duration = time.time() - scan_start
        print(f"Scanned {res['total_lines']} lines in {scan_duration:.4f} seconds.")
        print(f"Detected {res['failed_password_count']} auth failures, {res['error_count']} errors. Risk Score: {res['risk_score']}")
        
        assert res["total_lines"] == 50000
        assert scan_duration < 1.0, "Scan took too long!"
        print("Stress test passed successfully with high performance!")
    finally:
        os.unlink(path)

if __name__ == "__main__":
    test_large_log_stress()
