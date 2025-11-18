#!/usr/bin/env python3
"""
Standalone test runner for security_hardening module only
This bypasses the package imports that have dependency issues
"""

import sys
import os

# Directly import the security_hardening module without going through package __init__
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'onepassword_mcp_server'))

# Now we can import and run the tests
import pytest

# Run only the security hardening tests
if __name__ == "__main__":
    sys.exit(pytest.main([
        'onepassword_mcp_server/test_security_hardening.py',
        '-v',
        '--tb=short',
        '-W', 'ignore::DeprecationWarning'
    ]))
