#!/usr/bin/env python3
"""
Comprehensive test suite for security_hardening module

Tests cover:
- SecureString: Memory protection, lifecycle, expiration
- SecureMemoryManager: Allocation tracking, cleanup, garbage collection
- RequestSigner: HMAC signing, verification, key rotation
- TransportSecurityManager: TLS enforcement, cipher validation, CORS
- EnvironmentSecurityValidator: Environment validation, security headers
- SecurityHardeningManager: Integration testing
"""

import pytest
import time
import os
import sys
import ssl
import secrets
import threading
import base64
import hmac
import hashlib
from unittest.mock import MagicMock, patch, mock_open
from datetime import datetime, timedelta
from typing import Dict, Any

# Import the module to test directly (not through package __init__)
import sys
import os
# Add the parent directory to the path to import the module directly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from security_hardening import (
    SecurityHardeningConfig,
    SecureString,
    SecureMemoryManager,
    RequestSigner,
    TransportSecurityManager,
    EnvironmentSecurityValidator,
    SecurityHardeningManager,
    MemoryProtectionError,
    TransportSecurityError,
    RequestIntegrityError,
    EnvironmentSecurityError,
    SecurityError,
    initialize_security_hardening,
    get_security_manager,
    create_default_security_config,
)


class TestSecurityHardeningConfig:
    """Test SecurityHardeningConfig dataclass"""

    def test_default_config_values(self):
        """Test default configuration values are secure"""
        config = SecurityHardeningConfig()

        # Memory protection defaults
        assert config.memory_protection_enabled is True
        assert config.secure_memory_clear_on_exit is True
        assert config.credential_max_lifetime_seconds == 300  # 5 minutes

        # Transport security defaults
        assert config.tls_enforcement_enabled is True
        assert config.min_tls_version == "TLSv1.2"
        assert len(config.allowed_cipher_suites) > 0

        # Request signing defaults
        assert config.request_signing_enabled is True
        assert config.signature_algorithm == "SHA256"
        assert config.signature_key_rotation_hours == 24

        # Environment validation defaults
        assert config.environment_validation_enabled is True
        assert "OP_SERVICE_ACCOUNT_TOKEN" in config.required_environment_vars

        # CORS defaults
        assert config.cors_enabled is True
        assert "POST" in config.allowed_methods

    def test_custom_config_values(self):
        """Test custom configuration values"""
        config = SecurityHardeningConfig(
            memory_protection_enabled=False,
            tls_enforcement_enabled=False,
            min_tls_version="TLSv1.3",
            signature_key_rotation_hours=12,
            credential_max_lifetime_seconds=600
        )

        assert config.memory_protection_enabled is False
        assert config.tls_enforcement_enabled is False
        assert config.min_tls_version == "TLSv1.3"
        assert config.signature_key_rotation_hours == 12
        assert config.credential_max_lifetime_seconds == 600

    def test_create_default_security_config(self):
        """Test default config factory function"""
        config = create_default_security_config()
        assert isinstance(config, SecurityHardeningConfig)
        assert config.memory_protection_enabled is True


class TestSecureString:
    """Test SecureString class for memory protection"""

    def test_secure_string_initialization(self):
        """Test SecureString creation"""
        secret = SecureString("my_secret_password")
        assert secret.get_value() == "my_secret_password"
        assert secret._cleared is False

    def test_secure_string_empty_initialization(self):
        """Test SecureString with empty value"""
        secret = SecureString()
        assert secret.get_value() == ""
        assert secret._cleared is False

    def test_secure_string_set_value(self):
        """Test updating SecureString value"""
        secret = SecureString("initial")
        assert secret.get_value() == "initial"

        secret.set_value("updated")
        assert secret.get_value() == "updated"

    def test_secure_string_clear(self):
        """Test clearing SecureString"""
        secret = SecureString("sensitive_data")
        assert secret._cleared is False

        secret.clear()
        assert secret._cleared is True

        # Accessing cleared string should raise error
        with pytest.raises(MemoryProtectionError, match="has been cleared"):
            secret.get_value()

    def test_secure_string_double_clear(self):
        """Test clearing already cleared SecureString"""
        secret = SecureString("data")
        secret.clear()
        secret.clear()  # Should not raise error
        assert secret._cleared is True

    def test_secure_string_set_after_clear(self):
        """Test setting value on cleared SecureString"""
        secret = SecureString("data")
        secret.clear()

        with pytest.raises(MemoryProtectionError, match="Cannot set value on cleared"):
            secret.set_value("new_data")

    def test_secure_string_lifetime_expiration(self):
        """Test SecureString lifetime expiration"""
        secret = SecureString("temporary")
        secret._max_lifetime = 0.1  # 100ms for testing

        time.sleep(0.15)  # Wait for expiration

        with pytest.raises(MemoryProtectionError, match="lifetime exceeded"):
            secret.get_value()

        # Should be cleared after expiration
        assert secret._cleared is True

    def test_secure_string_memory_clearing(self):
        """Test that memory is actually overwritten"""
        secret = SecureString("sensitive123")
        original_data = secret._data

        secret.clear()

        # Data should be cleared (empty)
        assert len(secret._data) == 0

    def test_secure_string_str_representation(self):
        """Test string representation doesn't leak data"""
        secret = SecureString("secret_password")
        str_repr = str(secret)

        assert "secret_password" not in str_repr
        assert "PROTECTED" in str_repr

    def test_secure_string_repr_representation(self):
        """Test repr representation shows cleared status"""
        secret = SecureString("data")
        repr_before = repr(secret)
        assert "cleared=False" in repr_before

        secret.clear()
        repr_after = repr(secret)
        assert "cleared=True" in repr_after

    def test_secure_string_unicode_support(self):
        """Test SecureString with Unicode characters"""
        unicode_secret = SecureString("密码🔐")
        assert unicode_secret.get_value() == "密码🔐"

        unicode_secret.clear()
        assert unicode_secret._cleared is True

    def test_secure_string_deletion(self):
        """Test __del__ method clears memory"""
        secret = SecureString("will_be_deleted")
        secret_id = id(secret)

        # Delete the object
        del secret

        # Object should be garbage collected
        # (Can't directly verify memory is cleared, but __del__ should be called)


class TestSecureMemoryManager:
    """Test SecureMemoryManager class"""

    def test_memory_manager_initialization(self):
        """Test SecureMemoryManager initialization"""
        manager = SecureMemoryManager()
        assert manager is not None

        allocations = manager.get_active_allocations()
        assert allocations["count"] == 0
        assert len(allocations["allocations"]) == 0

    def test_allocate_secure_string(self):
        """Test allocating secure strings"""
        manager = SecureMemoryManager()

        secret1 = manager.allocate_secure_string("secret1")
        secret2 = manager.allocate_secure_string("secret2")

        assert secret1.get_value() == "secret1"
        assert secret2.get_value() == "secret2"

        allocations = manager.get_active_allocations()
        assert allocations["count"] == 2

    def test_allocation_tracking(self):
        """Test allocation metadata tracking"""
        manager = SecureMemoryManager()

        secret = manager.allocate_secure_string("tracked_secret")
        allocations = manager.get_active_allocations()

        assert allocations["count"] == 1
        assert len(allocations["allocations"]) == 1

        allocation_info = allocations["allocations"][0]
        assert allocation_info["id"] == id(secret)
        assert allocation_info["metadata"]["type"] == "SecureString"
        assert allocation_info["metadata"]["size"] == len("tracked_secret")
        assert "created_at" in allocation_info["metadata"]

    def test_weak_reference_cleanup(self):
        """Test that weak references are cleaned up"""
        manager = SecureMemoryManager()

        secret = manager.allocate_secure_string("temporary")
        assert manager.get_active_allocations()["count"] == 1

        # Delete the secret
        del secret
        manager.force_garbage_collection()

        # Weak reference should be gone
        allocations = manager.get_active_allocations()
        # The metadata might still exist, but the allocation should be cleaned
        # Check that the weak reference is gone
        assert len([a for a in allocations["allocations"]]) == 0

    def test_force_garbage_collection(self):
        """Test forced garbage collection"""
        manager = SecureMemoryManager()

        # Create and delete some secure strings
        for i in range(10):
            s = manager.allocate_secure_string(f"secret_{i}")
            del s

        manager.force_garbage_collection()

        # All should be cleaned up
        allocations = manager.get_active_allocations()
        assert allocations["count"] == 0

    def test_cleanup_all_secure_memory(self):
        """Test cleanup of all secure memory"""
        manager = SecureMemoryManager()

        secrets = []
        for i in range(5):
            secrets.append(manager.allocate_secure_string(f"secret_{i}"))

        assert manager.get_active_allocations()["count"] == 5

        # Cleanup all
        manager._cleanup_all_secure_memory()

        # All secrets should be cleared
        for secret in secrets:
            assert secret._cleared is True

        allocations = manager.get_active_allocations()
        assert allocations["count"] == 0

    def test_thread_safety(self):
        """Test thread-safe allocation"""
        manager = SecureMemoryManager()
        secrets = []
        errors = []

        def allocate_secrets():
            try:
                for i in range(10):
                    secret = manager.allocate_secure_string(f"thread_secret_{i}")
                    secrets.append(secret)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=allocate_secrets) for _ in range(5)]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        assert len(errors) == 0
        assert manager.get_active_allocations()["count"] == 50  # 5 threads * 10 secrets


class TestRequestSigner:
    """Test RequestSigner class"""

    def test_request_signer_initialization(self):
        """Test RequestSigner initialization"""
        config = SecurityHardeningConfig()
        signer = RequestSigner(config)

        assert signer.config == config
        assert len(signer._signing_key) == 32  # 256-bit key
        assert isinstance(signer._key_created_at, datetime)

    def test_sign_request(self):
        """Test request signing"""
        config = SecurityHardeningConfig()
        signer = RequestSigner(config)

        request_data = {
            "action": "get_credentials",
            "item_name": "github.com",
            "vault": "AI"
        }

        signature = signer.sign_request(request_data)

        assert signature is not None
        assert len(signature) > 0
        assert isinstance(signature, str)

        # Signature should be base64 encoded
        try:
            base64.b64decode(signature)
        except Exception:
            pytest.fail("Signature is not valid base64")

    def test_verify_request_valid(self):
        """Test valid request verification"""
        config = SecurityHardeningConfig()
        signer = RequestSigner(config)

        request_data = {
            "action": "get_credentials",
            "item_name": "test.com"
        }

        signature = signer.sign_request(request_data)
        is_valid = signer.verify_request(request_data, signature)

        assert is_valid is True

    def test_verify_request_invalid_signature(self):
        """Test invalid signature verification"""
        config = SecurityHardeningConfig()
        signer = RequestSigner(config)

        request_data = {"action": "get_credentials"}

        # Create a fake signature
        fake_signature = base64.b64encode(b"fake_signature").decode('ascii')
        is_valid = signer.verify_request(request_data, fake_signature)

        assert is_valid is False

    def test_verify_request_tampered_data(self):
        """Test verification fails with tampered data"""
        config = SecurityHardeningConfig()
        signer = RequestSigner(config)

        original_data = {"action": "get_credentials", "item_name": "test.com"}
        signature = signer.sign_request(original_data)

        # Tamper with data
        tampered_data = {"action": "get_credentials", "item_name": "evil.com"}
        is_valid = signer.verify_request(tampered_data, signature)

        assert is_valid is False

    def test_signing_disabled(self):
        """Test signing when disabled"""
        config = SecurityHardeningConfig(request_signing_enabled=False)
        signer = RequestSigner(config)

        request_data = {"action": "test"}
        signature = signer.sign_request(request_data)

        assert signature == ""

        # Verification should pass when disabled
        is_valid = signer.verify_request(request_data, "any_signature")
        assert is_valid is True

    def test_key_rotation_needed(self):
        """Test key rotation detection"""
        config = SecurityHardeningConfig(signature_key_rotation_hours=1)
        signer = RequestSigner(config)

        # Initially should not need rotation
        assert signer._should_rotate_key() is False

        # Simulate old key
        signer._key_created_at = datetime.utcnow() - timedelta(hours=2)
        assert signer._should_rotate_key() is True

    def test_key_rotation(self):
        """Test actual key rotation"""
        config = SecurityHardeningConfig(signature_key_rotation_hours=1)
        signer = RequestSigner(config)

        original_key = signer._signing_key

        # Force key rotation
        signer._key_created_at = datetime.utcnow() - timedelta(hours=2)
        signer._rotate_key_if_needed()

        # Key should be different
        assert signer._signing_key != original_key

    def test_canonical_request_format(self):
        """Test canonical request format is deterministic"""
        config = SecurityHardeningConfig()
        signer = RequestSigner(config)

        request1 = {"b": "2", "a": "1", "c": "3"}
        request2 = {"c": "3", "a": "1", "b": "2"}

        # Mock time.time to return consistent value
        with patch('time.time', return_value=1234567890):
            canonical1 = signer._canonicalize_request(request1)
            canonical2 = signer._canonicalize_request(request2)

        # Should be identical (keys sorted)
        assert canonical1 == canonical2

    def test_signature_different_algorithms(self):
        """Test signing with different algorithms"""
        for algorithm in ["SHA256", "SHA512"]:
            config = SecurityHardeningConfig(signature_algorithm=algorithm)
            signer = RequestSigner(config)

            request_data = {"test": "data"}
            signature = signer.sign_request(request_data)

            assert signature is not None
            assert len(signature) > 0


class TestTransportSecurityManager:
    """Test TransportSecurityManager class"""

    def test_transport_security_initialization(self):
        """Test TransportSecurityManager initialization"""
        config = SecurityHardeningConfig()
        manager = TransportSecurityManager(config)

        assert manager.config == config

    def test_create_secure_ssl_context_tls12(self):
        """Test creating SSL context with TLS 1.2"""
        config = SecurityHardeningConfig(min_tls_version="TLSv1.2")
        manager = TransportSecurityManager(config)

        context = manager.create_secure_ssl_context()

        assert isinstance(context, ssl.SSLContext)
        assert context.minimum_version == ssl.TLSVersion.TLSv1_2

    def test_create_secure_ssl_context_tls13(self):
        """Test creating SSL context with TLS 1.3"""
        config = SecurityHardeningConfig(min_tls_version="TLSv1.3")
        manager = TransportSecurityManager(config)

        context = manager.create_secure_ssl_context()

        assert isinstance(context, ssl.SSLContext)
        assert context.minimum_version == ssl.TLSVersion.TLSv1_3

    def test_create_ssl_context_invalid_version(self):
        """Test error with invalid TLS version"""
        config = SecurityHardeningConfig(min_tls_version="TLSv1.0")  # Old/insecure
        manager = TransportSecurityManager(config)

        with pytest.raises(TransportSecurityError, match="Unsupported TLS version"):
            manager.create_secure_ssl_context()

    def test_create_ssl_context_disabled(self):
        """Test error when TLS enforcement is disabled"""
        config = SecurityHardeningConfig(tls_enforcement_enabled=False)
        manager = TransportSecurityManager(config)

        with pytest.raises(TransportSecurityError, match="TLS enforcement is disabled"):
            manager.create_secure_ssl_context()

    def test_ssl_context_security_options(self):
        """Test SSL context has proper security options"""
        config = SecurityHardeningConfig()
        manager = TransportSecurityManager(config)

        context = manager.create_secure_ssl_context()

        # Check that insecure protocols are disabled
        # Note: OP_NO_SSLv2 may be 0 in modern OpenSSL (already disabled by default)
        # We only check SSLv3 and compression which should be set
        assert context.options & ssl.OP_NO_SSLv3
        assert context.options & ssl.OP_NO_COMPRESSION

    def test_generate_cors_headers_allowed_origin(self):
        """Test CORS header generation with allowed origin"""
        config = SecurityHardeningConfig(
            cors_enabled=True,
            allowed_origins=["https://example.com", "https://localhost"]
        )
        manager = TransportSecurityManager(config)

        headers = manager.generate_cors_headers("https://example.com")

        assert headers["Access-Control-Allow-Origin"] == "https://example.com"
        assert "POST" in headers["Access-Control-Allow-Methods"]
        assert "Content-Type" in headers["Access-Control-Allow-Headers"]
        assert headers["Access-Control-Max-Age"] == "3600"

    def test_generate_cors_headers_wildcard(self):
        """Test CORS headers with wildcard origin"""
        config = SecurityHardeningConfig(
            cors_enabled=True,
            allowed_origins=["*"]
        )
        manager = TransportSecurityManager(config)

        headers = manager.generate_cors_headers("https://any.com")

        assert headers["Access-Control-Allow-Origin"] == "*"

    def test_generate_cors_headers_disallowed_origin(self):
        """Test CORS headers with disallowed origin"""
        config = SecurityHardeningConfig(
            cors_enabled=True,
            allowed_origins=["https://example.com"]
        )
        manager = TransportSecurityManager(config)

        headers = manager.generate_cors_headers("https://evil.com")

        # Should not include Access-Control-Allow-Origin for disallowed origin
        assert "Access-Control-Allow-Origin" not in headers

    def test_generate_cors_headers_disabled(self):
        """Test CORS headers when CORS is disabled"""
        config = SecurityHardeningConfig(cors_enabled=False)
        manager = TransportSecurityManager(config)

        headers = manager.generate_cors_headers("https://example.com")

        assert headers == {}

    def test_validate_client_certificate_valid(self):
        """Test validating a valid client certificate"""
        # This would require creating actual certificate data
        # For now, test the error path
        config = SecurityHardeningConfig()
        manager = TransportSecurityManager(config)

        # Invalid cert data should return False
        is_valid = manager.validate_client_certificate(b"invalid_cert_data")
        assert is_valid is False


class TestEnvironmentSecurityValidator:
    """Test EnvironmentSecurityValidator class"""

    def test_validator_initialization(self):
        """Test EnvironmentSecurityValidator initialization"""
        config = SecurityHardeningConfig()
        validator = EnvironmentSecurityValidator(config)

        assert validator.config == config

    @patch.dict(os.environ, {"OP_SERVICE_ACCOUNT_TOKEN": "ops_test_token"}, clear=True)
    def test_validate_environment_success(self):
        """Test successful environment validation"""
        config = SecurityHardeningConfig(
            required_environment_vars=["OP_SERVICE_ACCOUNT_TOKEN"],
            forbidden_environment_patterns=[]
        )
        validator = EnvironmentSecurityValidator(config)

        is_valid, issues = validator.validate_environment()

        assert is_valid is True
        assert len(issues) == 0

    @patch.dict(os.environ, {}, clear=True)
    def test_validate_environment_missing_required_var(self):
        """Test validation fails with missing required variable"""
        config = SecurityHardeningConfig(
            required_environment_vars=["OP_SERVICE_ACCOUNT_TOKEN"],
            forbidden_environment_patterns=[]
        )
        validator = EnvironmentSecurityValidator(config)

        is_valid, issues = validator.validate_environment()

        assert is_valid is False
        assert len(issues) > 0
        assert any("OP_SERVICE_ACCOUNT_TOKEN" in issue for issue in issues)

    @patch.dict(os.environ, {
        "OP_SERVICE_ACCOUNT_TOKEN": "ops_test",
        "DEBUG_MODE": "true"
    }, clear=True)
    def test_validate_environment_forbidden_pattern(self):
        """Test validation detects forbidden environment patterns"""
        config = SecurityHardeningConfig(
            required_environment_vars=["OP_SERVICE_ACCOUNT_TOKEN"],
            forbidden_environment_patterns=["DEBUG_"]
        )
        validator = EnvironmentSecurityValidator(config)

        is_valid, issues = validator.validate_environment()

        assert is_valid is False
        assert any("DEBUG_MODE" in issue for issue in issues)

    @patch.dict(os.environ, {
        "OP_SERVICE_ACCOUNT_TOKEN": "ops_test",
        "DEBUG": "true"
    }, clear=True)
    def test_validate_environment_debug_indicators(self):
        """Test detection of debug/development indicators"""
        config = SecurityHardeningConfig(
            required_environment_vars=["OP_SERVICE_ACCOUNT_TOKEN"],
            forbidden_environment_patterns=[]
        )
        validator = EnvironmentSecurityValidator(config)

        is_valid, issues = validator.validate_environment()

        assert is_valid is False
        assert any("DEBUG" in issue for issue in issues)

    @patch.dict(os.environ, {"OP_SERVICE_ACCOUNT_TOKEN": "ops_test"}, clear=True)
    def test_validate_environment_disabled(self):
        """Test validation when disabled"""
        config = SecurityHardeningConfig(environment_validation_enabled=False)
        validator = EnvironmentSecurityValidator(config)

        is_valid, issues = validator.validate_environment()

        assert is_valid is True
        assert len(issues) == 0

    def test_get_security_headers(self):
        """Test security headers generation"""
        config = SecurityHardeningConfig()
        validator = EnvironmentSecurityValidator(config)

        headers = validator.get_security_headers()

        # Check for important security headers
        assert "Strict-Transport-Security" in headers
        assert "X-Content-Type-Options" in headers
        assert "X-Frame-Options" in headers
        assert "X-XSS-Protection" in headers
        assert "Content-Security-Policy" in headers

        # Check values
        assert headers["X-Frame-Options"] == "DENY"
        assert headers["X-Content-Type-Options"] == "nosniff"

    @patch('os.path.exists')
    @patch('os.stat')
    def test_validate_world_readable_file(self, mock_stat, mock_exists):
        """Test detection of world-readable sensitive files"""
        mock_exists.return_value = True

        # Mock file with world-readable permissions (0o644)
        mock_stat_result = MagicMock()
        mock_stat_result.st_mode = 0o100644  # Regular file with rw-r--r--
        mock_stat.return_value = mock_stat_result

        config = SecurityHardeningConfig(
            required_environment_vars=[],
            forbidden_environment_patterns=[]
        )
        validator = EnvironmentSecurityValidator(config)

        is_valid, issues = validator.validate_environment()

        # Should detect world-readable .env file
        assert is_valid is False
        assert any("world-readable" in issue for issue in issues)


class TestSecurityHardeningManager:
    """Test SecurityHardeningManager integration"""

    @patch.dict(os.environ, {"OP_SERVICE_ACCOUNT_TOKEN": "ops_test"}, clear=True)
    def test_manager_initialization_success(self):
        """Test successful SecurityHardeningManager initialization"""
        config = SecurityHardeningConfig(
            required_environment_vars=["OP_SERVICE_ACCOUNT_TOKEN"],
            forbidden_environment_patterns=[]
        )

        manager = SecurityHardeningManager(config)

        assert manager.config == config
        assert isinstance(manager.memory_manager, SecureMemoryManager)
        assert isinstance(manager.request_signer, RequestSigner)
        assert isinstance(manager.transport_security, TransportSecurityManager)
        assert isinstance(manager.environment_validator, EnvironmentSecurityValidator)

    @patch.dict(os.environ, {}, clear=True)
    def test_manager_initialization_failure(self):
        """Test SecurityHardeningManager fails with invalid environment"""
        config = SecurityHardeningConfig(
            required_environment_vars=["OP_SERVICE_ACCOUNT_TOKEN"]
        )

        with pytest.raises(EnvironmentSecurityError, match="Environment validation failed"):
            SecurityHardeningManager(config)

    @patch.dict(os.environ, {"OP_SERVICE_ACCOUNT_TOKEN": "ops_test"}, clear=True)
    def test_secure_credential_context(self):
        """Test secure credential context manager"""
        config = SecurityHardeningConfig(
            required_environment_vars=["OP_SERVICE_ACCOUNT_TOKEN"],
            forbidden_environment_patterns=[]
        )
        manager = SecurityHardeningManager(config)

        credential_data = "secret_password_123"

        with manager.secure_credential_context(credential_data) as secure_cred:
            assert isinstance(secure_cred, SecureString)
            assert secure_cred.get_value() == credential_data

        # After context, credential should be cleared
        assert secure_cred._cleared is True

    @patch.dict(os.environ, {"OP_SERVICE_ACCOUNT_TOKEN": "ops_test"}, clear=True)
    def test_create_secure_request_context(self):
        """Test creating secure request context"""
        config = SecurityHardeningConfig(
            required_environment_vars=["OP_SERVICE_ACCOUNT_TOKEN"],
            forbidden_environment_patterns=[]
        )
        manager = SecurityHardeningManager(config)

        request_data = {
            "action": "get_credentials",
            "item_name": "test.com"
        }

        secure_request = manager.create_secure_request_context(request_data)

        assert "action" in secure_request
        assert "timestamp" in secure_request
        assert "request_id" in secure_request
        assert "signature" in secure_request
        assert len(secure_request["request_id"]) == 32  # 16 bytes hex = 32 chars

    @patch.dict(os.environ, {"OP_SERVICE_ACCOUNT_TOKEN": "ops_test"}, clear=True)
    def test_validate_request_context(self):
        """Test validating request context"""
        config = SecurityHardeningConfig(
            required_environment_vars=["OP_SERVICE_ACCOUNT_TOKEN"],
            forbidden_environment_patterns=[]
        )
        manager = SecurityHardeningManager(config)

        request_data = {"action": "test"}
        secure_request = manager.create_secure_request_context(request_data)

        # Should validate successfully
        is_valid = manager.validate_request_context(secure_request.copy())
        assert is_valid is True

    @patch.dict(os.environ, {"OP_SERVICE_ACCOUNT_TOKEN": "ops_test"}, clear=True)
    def test_validate_request_context_tampered(self):
        """Test validation fails with tampered request"""
        config = SecurityHardeningConfig(
            required_environment_vars=["OP_SERVICE_ACCOUNT_TOKEN"],
            forbidden_environment_patterns=[]
        )
        manager = SecurityHardeningManager(config)

        request_data = {"action": "test"}
        secure_request = manager.create_secure_request_context(request_data)

        # Tamper with the request
        secure_request["action"] = "malicious"

        is_valid = manager.validate_request_context(secure_request)
        assert is_valid is False

    @patch.dict(os.environ, {"OP_SERVICE_ACCOUNT_TOKEN": "ops_test"}, clear=True)
    def test_get_security_status(self):
        """Test getting security status"""
        config = SecurityHardeningConfig(
            required_environment_vars=["OP_SERVICE_ACCOUNT_TOKEN"],
            forbidden_environment_patterns=[]
        )
        manager = SecurityHardeningManager(config)

        status = manager.get_security_status()

        assert "environment_valid" in status
        assert "environment_issues" in status
        assert "memory_allocations" in status
        assert "transport_security_enabled" in status
        assert "request_signing_enabled" in status
        assert "cors_enabled" in status
        assert "config" in status

        assert status["environment_valid"] is True
        assert status["transport_security_enabled"] is True

    @patch.dict(os.environ, {"OP_SERVICE_ACCOUNT_TOKEN": "ops_test"}, clear=True)
    def test_cleanup(self):
        """Test cleanup of security resources"""
        config = SecurityHardeningConfig(
            required_environment_vars=["OP_SERVICE_ACCOUNT_TOKEN"],
            forbidden_environment_patterns=[]
        )
        manager = SecurityHardeningManager(config)

        # Create some secure strings
        with manager.secure_credential_context("test1"):
            pass
        with manager.secure_credential_context("test2"):
            pass

        # Cleanup
        manager.cleanup()

        # All allocations should be cleaned
        allocations = manager.memory_manager.get_active_allocations()
        assert allocations["count"] == 0


class TestGlobalFunctions:
    """Test global initialization functions"""

    @patch.dict(os.environ, {"OP_SERVICE_ACCOUNT_TOKEN": "ops_test"}, clear=True)
    def test_initialize_security_hardening(self):
        """Test global security hardening initialization"""
        config = SecurityHardeningConfig(
            required_environment_vars=["OP_SERVICE_ACCOUNT_TOKEN"],
            forbidden_environment_patterns=[]
        )

        manager = initialize_security_hardening(config)

        assert isinstance(manager, SecurityHardeningManager)
        assert get_security_manager() is manager

    def test_get_security_manager_not_initialized(self):
        """Test getting security manager when not initialized"""
        # Reset global
        import security_hardening as sh_module
        sh_module._security_manager = None

        manager = get_security_manager()
        assert manager is None


class TestEdgeCases:
    """Test edge cases and error conditions"""

    def test_secure_string_with_very_long_data(self):
        """Test SecureString with large data"""
        large_data = "x" * 10000
        secret = SecureString(large_data)

        assert secret.get_value() == large_data
        secret.clear()
        assert secret._cleared is True

    def test_secure_string_with_special_characters(self):
        """Test SecureString with special characters"""
        special = "!@#$%^&*()[]{}|\\;:'\"<>,.?/~`"
        secret = SecureString(special)

        assert secret.get_value() == special

    @patch.dict(os.environ, {"OP_SERVICE_ACCOUNT_TOKEN": "ops_test"}, clear=True)
    def test_concurrent_request_signing(self):
        """Test concurrent request signing"""
        config = SecurityHardeningConfig(
            required_environment_vars=["OP_SERVICE_ACCOUNT_TOKEN"],
            forbidden_environment_patterns=[]
        )
        manager = SecurityHardeningManager(config)

        signatures = []
        errors = []

        def sign_requests():
            try:
                for i in range(10):
                    request = {"index": i}
                    secure_req = manager.create_secure_request_context(request)
                    signatures.append(secure_req["signature"])
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=sign_requests) for _ in range(5)]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        assert len(errors) == 0
        assert len(signatures) == 50  # 5 threads * 10 signatures
        # All signatures should be non-empty
        assert all(sig for sig in signatures)


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "--tb=short"])
