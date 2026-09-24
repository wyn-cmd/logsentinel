import re
import json

class LogScanner:
    MAX_ANOMALIES = 500

    PATTERNS = {
        "failed_password": re.compile(r"failed password|authentication failure|invalid user", re.IGNORECASE),
        "sudo_anomaly": re.compile(r"sudo|su:", re.IGNORECASE),
        "error_spike": re.compile(r"error|critical|fatal|exception", re.IGNORECASE),
    }

    CHECK_MAPPINGS = [
        ("failed_password", "AUTH_FAILURE", 5, "failed_password_count"),
        ("sudo_anomaly", "SUDO_ACTIVITY", 2, "sudo_anomaly_count"),
        ("error_spike", "ERROR_INDICATOR", 3, "error_count"),
    ]

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
            with open(self.filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, 1):
                    results["total_lines"] += 1
                    cleaned = line.strip()
                    if not cleaned:
                        continue
                    
                    for pattern_key, anomaly_type, score_val, count_key in self.CHECK_MAPPINGS:
                        if self.PATTERNS[pattern_key].search(cleaned):
                            results[count_key] += 1
                            results["risk_score"] += score_val
                            if len(results["anomalies"]) < self.MAX_ANOMALIES:
                                results["anomalies"].append({
                                    "line": line_num,
                                    "type": anomaly_type,
                                    "content": cleaned
                                })
                            
        except OSError as e:
            results["error"] = f"File error: {e}"
        except Exception as e:
            results["error"] = str(e)
            
        return results