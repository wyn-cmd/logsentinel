import re
import json

class LogScanner:
    PATTERNS = {
        "failed_password": re.compile(r"failed password|authentication failure|invalid user", re.IGNORECASE),
        "sudo_anomaly": re.compile(r"sudo|su:", re.IGNORECASE),
        "error_spike": re.compile(r"error|critical|fatal|exception", re.IGNORECASE)
    }

    def __init__(self, filepath):
        self.filepath = filepath

    def scan(self):
        results = {
            "total_lines": 0,
            "failed_password_count": 0,
            "sudo_anomaly_count": 0,
            "error_count": 0,
            "risk_score": 0,
            "anomalies": []
        }
        
        try:
            with open(self.filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    results["total_lines"] += 1
                    cleaned = line.strip()
                    
                    matched = False
                    if self.PATTERNS["failed_password"].search(cleaned):
                        results["failed_password_count"] += 1
                        results["risk_score"] += 5
                        results["anomalies"].append({"line": line_num, "type": "AUTH_FAILURE", "content": cleaned})
                        matched = True
                    if self.PATTERNS["sudo_anomaly"].search(cleaned):
                        results["sudo_anomaly_count"] += 1
                        results["risk_score"] += 2
                        results["anomalies"].append({"line": line_num, "type": "SUDO_ACTIVITY", "content": cleaned})
                        matched = True
                    if self.PATTERNS["error_spike"].search(cleaned):
                        results["error_count"] += 1
                        results["risk_score"] += 3
                        results["anomalies"].append({"line": line_num, "type": "ERROR_INDICATOR", "content": cleaned})
                        matched = True
        except Exception as e:
            results["error"] = str(e)
            
        return results
