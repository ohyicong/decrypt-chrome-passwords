import pytest
import tempfile
import shutil
import os
import json
from pathlib import Path
from unittest.mock import Mock, patch


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    temp_path = tempfile.mkdtemp()
    yield temp_path
    shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def mock_chrome_paths(temp_dir, monkeypatch):
    """Mock Chrome paths to use temporary directory."""
    chrome_user_data = os.path.join(temp_dir, "Chrome", "User Data")
    os.makedirs(chrome_user_data, exist_ok=True)
    
    # Create Local State file
    local_state_path = os.path.join(chrome_user_data, "Local State")
    local_state_data = {
        "os_crypt": {
            "encrypted_key": "RFBBUEkBAAAA0Iyd3wEV0RGMegDAT8KX6wEAAAAA"
        }
    }
    with open(local_state_path, 'w') as f:
        json.dump(local_state_data, f)
    
    # Create Default profile directory
    default_profile = os.path.join(chrome_user_data, "Default")
    os.makedirs(default_profile, exist_ok=True)
    
    # Mock environment variable
    monkeypatch.setenv("USERPROFILE", temp_dir)
    
    return {
        "user_data": chrome_user_data,
        "local_state": local_state_path,
        "default_profile": default_profile
    }


@pytest.fixture
def mock_sqlite_db(temp_dir):
    """Create a mock SQLite database for testing."""
    import sqlite3
    
    db_path = os.path.join(temp_dir, "Login Data")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create logins table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logins (
            origin_url TEXT NOT NULL,
            action_url TEXT,
            username_element TEXT,
            username_value TEXT,
            password_element TEXT,
            password_value BLOB,
            submit_element TEXT,
            signon_realm TEXT NOT NULL,
            date_created INTEGER NOT NULL,
            blacklisted_by_user INTEGER NOT NULL,
            scheme INTEGER NOT NULL
        )
    ''')
    
    conn.commit()
    conn.close()
    
    return db_path


@pytest.fixture
def mock_win32crypt():
    """Mock win32crypt module for non-Windows testing."""
    with patch('win32crypt.CryptUnprotectData') as mock_crypt:
        mock_crypt.return_value = (b'mock_decrypted_key', None)
        yield mock_crypt


@pytest.fixture
def sample_encrypted_password():
    """Provide a sample encrypted password for testing."""
    # This is a mock encrypted password structure
    # In reality, this would be properly encrypted data
    return b'v10' + b'0' * 12 + b'encrypted_data' + b'0' * 16


@pytest.fixture
def mock_csv_file(temp_dir):
    """Create a temporary CSV file for testing."""
    csv_path = os.path.join(temp_dir, "test_passwords.csv")
    return csv_path


@pytest.fixture
def isolated_filesystem(temp_dir, monkeypatch):
    """Isolate filesystem operations to temp directory."""
    original_cwd = os.getcwd()
    os.chdir(temp_dir)
    monkeypatch.setattr('os.getcwd', lambda: temp_dir)
    yield temp_dir
    os.chdir(original_cwd)


@pytest.fixture
def mock_aes_cipher():
    """Mock AES cipher for testing decryption."""
    mock_cipher = Mock()
    mock_cipher.decrypt.return_value = b'decrypted_password'
    return mock_cipher


@pytest.fixture(autouse=True)
def cleanup_test_files():
    """Automatically clean up test files after each test."""
    yield
    # Clean up any leftover test files
    test_files = ['Loginvault.db', 'decrypted_password.csv']
    for file in test_files:
        if os.path.exists(file):
            try:
                os.remove(file)
            except:
                pass