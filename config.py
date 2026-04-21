import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")
BASELINE_FILE = os.path.join(BASE_DIR, "baselines.json")
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  
SECURITY_HEADERS = {
    "X-Frame-Options": "SAMEORIGIN",
    "X-Content-Type-Options": "nosniff",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
}
MAGIC_BYTES = b"CYBRGUARD"   
PBKDF2_ITERATIONS = 120_000  
AES_KEY_LENGTH = 32          
SALT_LENGTH = 16
IV_LENGTH = 16
USER_AGENT = "CyberGuard-Pro/1.0 (Authorized Security Scanner)"
SCAN_TIMEOUT = 10
PROBE_TIMEOUT = 3
PORT_SCAN_THREADS = 100
SUBDOMAIN_THREADS = 20
WELL_KNOWN_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}
SQL_PAYLOADS = [
    "'", '"', "' OR '1'='1", "' OR 1=1--",
    "\" OR \"\"=\"", "1; DROP TABLE users--",
]
SQL_ERRORS = [
    "mysql_fetch", "ORA-", "SQL syntax", "Warning: mysql",
    "PostgreSQL", "SQLite", "ODBC SQL", "Unclosed quotation",
]
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
]
SECURITY_HEADERS_CHECK = [
    "X-Frame-Options", "X-XSS-Protection",
    "Content-Security-Policy", "Strict-Transport-Security",
    "X-Content-Type-Options", "Referrer-Policy",
    "Permissions-Policy",
]
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop",
    "ns1", "webdisk", "ns2", "cpanel", "whm", "autodiscover",
    "autoconfig", "m", "imap", "test", "ns", "blog", "pop3",
    "dev", "www2", "admin", "forum", "news", "vpn", "js", "api",
    "support", "billing",
]
SENSITIVE_PATHS = [
    "/admin", "/.env", "/config", "/backup",
    "/phpinfo.php", "/wp-admin",
]
