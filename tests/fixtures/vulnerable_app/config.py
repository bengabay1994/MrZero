"""Configuration file with hardcoded secrets - INTENTIONALLY VULNERABLE.

This file contains hardcoded credentials for MrZero testing.
DO NOT use these patterns in real applications.
"""

# =============================================================================
# VULNERABILITY: Hardcoded Secrets
# CWE-798: Use of Hard-coded Credentials
# =============================================================================

# Database configuration
DATABASE_PATH = "/tmp/vulnerable_app.db"

# VULNERABLE: Hardcoded API keys
SECRET_API_KEY = "sk-live-abc123def456ghi789jkl012mno345pqr678"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# VULNERABLE: Hardcoded database credentials
DB_USERNAME = "admin"
DB_PASSWORD = "SuperSecretPassword123!"
DB_HOST = "production-db.example.com"

# VULNERABLE: Hardcoded JWT secret
JWT_SECRET = "my-super-secret-jwt-key-that-should-not-be-here"

# VULNERABLE: Hardcoded OAuth credentials
OAUTH_CLIENT_ID = "1234567890-abcdefghijklmnop.apps.googleusercontent.com"
OAUTH_CLIENT_SECRET = "GOCSPX-abcdefghijklmnopqrstuvwxyz"

# VULNERABLE: Hardcoded encryption key
ENCRYPTION_KEY = "AES256-KEY-0123456789ABCDEF"

# VULNERABLE: Hardcoded private key (truncated for brevity)
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MvXxjhnFBnJVFyx0
bPHo5bWLEE7UpfkKH3WKzHjHdXLNOEjXjAlic7X0BcDrFABSVGSXGpBLOVPYCUKI
-----END RSA PRIVATE KEY-----"""

# VULNERABLE: Hardcoded Stripe key
STRIPE_SECRET_KEY = "sk_live_51HxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxX"
STRIPE_PUBLISHABLE_KEY = "pk_live_51HxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxX"

# VULNERABLE: Hardcoded SendGrid API key
SENDGRID_API_KEY = "SG.xxxxxxxxxxxxxxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# VULNERABLE: Hardcoded Twilio credentials
TWILIO_ACCOUNT_SID = "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
TWILIO_AUTH_TOKEN = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# VULNERABLE: Slack webhook URL
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"

# VULNERABLE: GitHub token
GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# VULNERABLE: Generic password in config
ADMIN_PASSWORD = "admin123"
ROOT_PASSWORD = "toor"
