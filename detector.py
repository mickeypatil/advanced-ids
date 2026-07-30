import re
from typing import Tuple

class ThreatDetector:
    def __init__(self):
        self.sql_patterns = [
            r"(?i)union.*select",
            r"(?i)select.*from.*where",
            r"(?i)drop.*table",
            r"(?i)1\s*=\s*1",
            r"(?i)or\s*1\s*=\s*1",
        ]
        
        self.xss_patterns = [
            r"<script[^>]*>",
            r"javascript:",
            r"on\w+\s*=",
            r"<iframe[^>]*>",
        ]

    def detect_sql_injection(self, payload: str) -> Tuple[bool, str]:
        for pattern in self.sql_patterns:
            if re.search(pattern, payload):
                return True, f"SQL Injection detected: {pattern}"
        return False, ""

    def detect_xss(self, payload: str) -> Tuple[bool, str]:
        for pattern in self.xss_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return True, f"XSS detected: {pattern}"
        return False, ""

# Test it
if __name__ == "__main__":
    detector = ThreatDetector()
    
    # Test SQL injection
    test1 = "SELECT * FROM users WHERE id=1 OR 1=1"
    is_sqli, reason = detector.detect_sql_injection(test1)
    print(f"SQL Injection Test: {is_sqli} - {reason}")
    
    # Test XSS
    test2 = "<script>alert(\"xss\")</script>"
    is_xss, reason = detector.detect_xss(test2)
    print(f"XSS Test: {is_xss} - {reason}")
