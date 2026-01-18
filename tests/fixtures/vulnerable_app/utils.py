"""Utility functions with security vulnerabilities - INTENTIONALLY VULNERABLE.

This module contains functions with path traversal and other vulnerabilities.
DO NOT use these patterns in real applications.
"""

import os

# Base directory for user files
USER_FILES_DIR = "/tmp/user_files"


# =============================================================================
# VULNERABILITY: Path Traversal
# CWE-22: Improper Limitation of a Pathname to a Restricted Directory
# =============================================================================
def read_user_file(filename: str) -> str:
    """Read a user file - VULNERABLE TO PATH TRAVERSAL.

    Args:
        filename: Name of the file to read.

    Returns:
        Content of the file.

    Example attack: filename = "../../../etc/passwd"
    """
    # VULNERABLE: No validation of filename, allows directory traversal
    file_path = os.path.join(USER_FILES_DIR, filename)

    # VULNERABLE: Should use os.path.realpath() and verify path is within allowed directory
    with open(file_path, "r") as f:
        return f.read()


def write_user_file(filename: str, content: str) -> bool:
    """Write a user file - VULNERABLE TO PATH TRAVERSAL.

    Args:
        filename: Name of the file to write.
        content: Content to write.

    Returns:
        True if successful.
    """
    # VULNERABLE: No validation of filename
    file_path = os.path.join(USER_FILES_DIR, filename)

    with open(file_path, "w") as f:
        f.write(content)

    return True


def delete_user_file(filename: str) -> bool:
    """Delete a user file - VULNERABLE TO PATH TRAVERSAL.

    Args:
        filename: Name of the file to delete.

    Returns:
        True if successful.
    """
    # VULNERABLE: No validation, could delete system files
    file_path = os.path.join(USER_FILES_DIR, filename)
    os.remove(file_path)
    return True


# =============================================================================
# VULNERABILITY: Unsafe File Operations
# CWE-73: External Control of File Name or Path
# =============================================================================
def get_log_file(log_name: str) -> str:
    """Get log file path - VULNERABLE.

    Args:
        log_name: Name of the log file.

    Returns:
        Full path to log file.
    """
    # VULNERABLE: User-controlled file path
    return f"/var/log/{log_name}"


def execute_script(script_name: str) -> str:
    """Execute a script - VULNERABLE TO PATH INJECTION.

    Args:
        script_name: Name of script to execute.

    Returns:
        Script output.
    """
    import subprocess

    # VULNERABLE: User-controlled script path
    script_path = f"/opt/scripts/{script_name}"

    result = subprocess.run(["bash", script_path], capture_output=True, text=True)

    return result.stdout


# =============================================================================
# VULNERABILITY: Insecure Temporary File
# CWE-377: Insecure Temporary File
# =============================================================================
def create_temp_file(content: str) -> str:
    """Create a temporary file - VULNERABLE.

    Args:
        content: Content to write.

    Returns:
        Path to temp file.
    """
    import tempfile

    # VULNERABLE: Predictable temporary file name
    temp_path = f"/tmp/app_temp_{os.getpid()}.txt"

    with open(temp_path, "w") as f:
        f.write(content)

    return temp_path


# =============================================================================
# VULNERABILITY: Unsafe Eval
# CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code
# =============================================================================
def calculate_expression(expression: str) -> float:
    """Calculate a mathematical expression - VULNERABLE TO CODE INJECTION.

    Args:
        expression: Mathematical expression to evaluate.

    Returns:
        Result of calculation.

    Example attack: expression = "__import__('os').system('whoami')"
    """
    # VULNERABLE: Using eval on user input
    return eval(expression)


def process_template(template: str, variables: dict) -> str:
    """Process a template string - VULNERABLE.

    Args:
        template: Template string with {variable} placeholders.
        variables: Dictionary of variables.

    Returns:
        Processed template.
    """
    # VULNERABLE: Using format with user-controlled template
    # Can leak sensitive data via {variable.__class__.__mro__}
    return template.format(**variables)


# =============================================================================
# VULNERABILITY: Weak Cryptography
# CWE-327: Use of a Broken or Risky Cryptographic Algorithm
# =============================================================================
def hash_password(password: str) -> str:
    """Hash a password - VULNERABLE: Uses weak algorithm.

    Args:
        password: Password to hash.

    Returns:
        Hashed password.
    """
    import hashlib

    # VULNERABLE: MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()


def encrypt_data(data: str, key: str) -> bytes:
    """Encrypt data - VULNERABLE: Weak encryption.

    Args:
        data: Data to encrypt.
        key: Encryption key.

    Returns:
        Encrypted data.
    """
    # VULNERABLE: Simple XOR "encryption" is not secure
    encrypted = bytes([ord(c) ^ ord(key[i % len(key)]) for i, c in enumerate(data)])
    return encrypted


# =============================================================================
# VULNERABILITY: Race Condition
# CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
# =============================================================================
def safe_write_file(filepath: str, content: str) -> bool:
    """Write file if it doesn't exist - VULNERABLE TO RACE CONDITION.

    Args:
        filepath: Path to file.
        content: Content to write.

    Returns:
        True if file was written.
    """
    # VULNERABLE: TOCTOU race condition between check and write
    if not os.path.exists(filepath):
        # Window of vulnerability here - file could be created between check and write
        with open(filepath, "w") as f:
            f.write(content)
        return True
    return False
