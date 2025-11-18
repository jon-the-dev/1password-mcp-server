#!/bin/bash
# Script to create GitHub issues from TODO.md security review findings
# Run this script to create all 28 security issues

# Critical Severity Issues

gh issue create \
  --title "[CRITICAL] C-1: Credential Bypass in Secure Memory Protection" \
  --label "security,critical,bug" \
  --body "**File:** \`onepassword_mcp_server/server.py\`
**Lines:** 364-385

**Description:**
The secure memory protection is bypassed when credentials are returned. After wrapping the password in a \`SecureString\` context, the code immediately extracts it with \`secure_password.get_value()\` and returns it in a plain dictionary, completely defeating the purpose of secure memory management.

\`\`\`python
# Lines 364-375
if security_manager:
    with security_manager.secure_credential_context(password) as secure_password:
        # Return credentials with secure handling
        return {
            \"username\": username,
            \"password\": secure_password.get_value(),  # ❌ Defeats secure memory!
            ...
        }
\`\`\`

**Impact:**
- Credentials remain in plaintext in Python memory
- No protection against memory dumps or core dumps
- SecureString cleanup happens before credentials are used
- False sense of security

**Recommendation:**
Either:
1. Return the \`SecureString\` object directly and require callers to extract values when needed, OR
2. Document that secure memory is not actually protecting returned credentials and remove the misleading implementation, OR
3. Implement true end-to-end secure memory by keeping credentials encrypted until the final use point

**Priority:** CRITICAL - Fix immediately"

gh issue create \
  --title "[CRITICAL] C-2: No Authentication or Authorization for MCP Tools" \
  --label "security,critical,enhancement" \
  --body "**File:** \`onepassword_mcp_server/server.py\`
**Lines:** 1384-1478 (tool registrations)

**Description:**
The MCP server has NO authentication or authorization mechanism beyond the 1Password service account token. Any process that can connect to the MCP server can:
- Retrieve any credential from any accessible vault
- Access health status and metrics
- Execute destructive operations (if enabled)

**Impact:**
- Any local process can access credentials
- No user accountability or audit trail
- No way to restrict which AI assistant or user can access which credentials
- Violates principle of least privilege

**Recommendation:**
Implement at minimum:
1. **Authentication layer**: Require API keys or tokens for MCP tool access
2. **Authorization layer**: Role-based access control (RBAC) for vaults and operations
3. **Audit logging**: Track WHICH user/client accessed WHICH credentials WHEN
4. **Session management**: Time-limited access tokens

**Priority:** CRITICAL - Required for production use"

gh issue create \
  --title "[CRITICAL] C-3: Service Account Token Stored in Plaintext Memory" \
  --label "security,critical,bug" \
  --body "**File:** \`onepassword_mcp_server/config.py\`
**Lines:** 170, 220, 246

**Description:**
The 1Password service account token is:
1. Loaded from environment variables into a Python string (immutable, cannot be cleared)
2. Stored in the \`ServerConfig\` dataclass without any memory protection
3. Passed around the application in plaintext
4. Never cleared from memory

\`\`\`python
# Line 220
service_account_token = os.getenv(\"OP_SERVICE_ACCOUNT_TOKEN\")  # Plaintext string

# Line 170
service_account_token: Optional[str] = None  # No secure storage
\`\`\`

**Impact:**
- Token exposed in memory dumps
- Token exposed in crash dumps
- Token may be swapped to disk
- Token visible in debuggers and profilers

**Recommendation:**
1. Use \`SecureString\` for the service account token
2. Implement memory locking (mlock/VirtualLock) for the token
3. Clear token from memory on shutdown
4. Consider using environment variable only at startup, then clearing it

**Priority:** CRITICAL - Especially for production deployments"

# High Severity Issues

gh issue create \
  --title "[HIGH] H-1: Plaintext Password Logging in Debug Mode" \
  --label "security,high,bug" \
  --body "**File:** \`onepassword_mcp_server/server.py\`
**Lines:** 332-342

**Description:**
In debug mode, the code logs the complete 1Password reference paths including vault and item names. While not logging the actual password, this reveals the vault structure and credential locations.

\`\`\`python
logger.debug(
    \"Retrieving credentials from 1Password\",
    operation=\"resolve_credentials\",
    metadata={
        \"username_ref\": username_ref,  # op://VaultName/ItemName/username
        \"password_ref\": password_ref    # op://VaultName/ItemName/password
    }
)
\`\`\`

**Impact:**
- Information leakage about credential organization
- Potential reconnaissance for attackers
- Logs may be sent to external logging services

**Recommendation:**
- Remove or redact vault and item names from debug logs
- Only log operation types, not specific references
- Add configuration flag to control debug verbosity

**Priority:** HIGH"

gh issue create \
  --title "[HIGH] H-2: Incomplete Sensitive Data Scrubbing" \
  --label "security,high,bug" \
  --body "**File:** \`onepassword_mcp_server/structured_logging.py\`
**Lines:** 64-122

**Description:**
The sensitive data scrubber has multiple weaknesses:

1. **Exact key matching only** (line 86): Only scrubs if the key name exactly matches patterns
2. **Limited pattern coverage** (lines 66-70): Missing common patterns like \`credential\`, \`auth_token\`, \`access_key\`
3. **No value-based detection**: Cannot detect sensitive data by content (e.g., JWT tokens, API keys)
4. **Regex bypass** (lines 105-111): Complex regex can be bypassed with unusual formatting

\`\`\`python
def _is_sensitive_key(self, key: str) -> bool:
    \"\"\"Check if key indicates sensitive data\"\"\"
    key_lower = key.lower()

    # Always scrub certain fields
    if key_lower in self.always_scrub:  # ❌ Only exact matches
        return True
\`\`\`

**Impact:**
- Sensitive data may leak through logs
- Credentials could be exposed with creative key names
- Third-party logging aggregators may receive secrets

**Recommendation:**
1. Add fuzzy matching for key names (substring matching)
2. Implement value-based detection (entropy analysis, format recognition)
3. Add more patterns: \`credential\`, \`bearer\`, \`auth_header\`, \`x-api-key\`
4. Scrub all values >20 chars with high entropy by default

**Priority:** HIGH"

gh issue create \
  --title "[HIGH] H-3: Request Signing Not Actually Verified" \
  --label "security,high,bug" \
  --body "**File:** \`onepassword_mcp_server/security_hardening.py\`
**Lines:** 284-297, \`server.py\` lines 298-300

**Description:**
The code implements request signing but never actually VERIFIES signatures on incoming requests. The \`create_secure_request_context\` adds a signature, but there's no enforcement that requests must have valid signatures.

\`\`\`python
# security_hardening.py - Signs requests
def create_secure_request_context(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
    signature = self.request_signer.sign_request(enhanced_request)
    enhanced_request[\"signature\"] = signature
    return enhanced_request

# ❌ But server.py never calls validate_request_context!
\`\`\`

**Impact:**
- Request tampering possible
- Replay attacks possible
- No integrity verification
- Security theater (looks secure but isn't)

**Recommendation:**
1. Add middleware to verify ALL incoming request signatures
2. Reject requests with missing or invalid signatures
3. Implement nonce/timestamp checking to prevent replay attacks
4. Add signature verification to the MCP tool handlers

**Priority:** HIGH"

gh issue create \
  --title "[HIGH] H-4: Timestamp-Based Signature Vulnerable to Replay Attacks" \
  --label "security,high,bug" \
  --body "**File:** \`onepassword_mcp_server/security_hardening.py\`
**Lines:** 299-309

**Description:**
The request signing uses current timestamp but doesn't validate timestamp freshness or prevent replay attacks:

\`\`\`python
def _canonicalize_request(self, request_data: Dict[str, Any]) -> str:
    canonical_json = json.dumps(request_data, sort_keys=True, separators=(',', ':'))
    timestamp = str(int(time.time()))  # ❌ No validation on receiving end
    return f\"{canonical_json}|{timestamp}\"
\`\`\`

**Impact:**
- Signed requests can be replayed indefinitely
- Old signatures remain valid forever
- No protection against MITM replay attacks

**Recommendation:**
1. Implement nonce-based signatures (one-time use tokens)
2. Add timestamp validation with maximum age (e.g., 5 minutes)
3. Maintain a cache of recently used nonces
4. Reject requests with timestamps too old or in the future

**Priority:** HIGH"

gh issue create \
  --title "[HIGH] H-5: Global Mutable State in Concurrent Environment" \
  --label "security,high,bug,technical-debt" \
  --body "**File:** \`onepassword_mcp_server/server.py\`
**Lines:** 68-77

**Description:**
The server uses global mutable variables for critical components:

\`\`\`python
config: Optional[ServerConfig] = None
logger = None
metrics_collector = None
secure_client: Optional[OnePasswordSecureClient] = None
# ... etc
\`\`\`

**Impact:**
- Race conditions in async context
- State corruption if multiple initializations occur
- Difficult to test and mock
- Not thread-safe

**Recommendation:**
1. Use dependency injection instead of globals
2. Implement singleton pattern with thread locking
3. Use \`contextvars\` for request-scoped state
4. Make components immutable after initialization

**Priority:** HIGH"

gh issue create \
  --title "[HIGH] H-6: Inadequate Input Validation - ReDoS Vulnerability" \
  --label "security,high,bug" \
  --body "**File:** \`onepassword_mcp_server/config.py\`
**Lines:** 87, 248

**Description:**
The regex pattern for item/vault names is vulnerable to Regular Expression Denial of Service (ReDoS):

\`\`\`python
allowed_item_name_pattern: str = r'^[a-zA-Z0-9._-]+$'  # ❌ Vulnerable to ReDoS
\`\`\`

While this specific pattern is relatively safe, there's no timeout protection and no maximum length enforcement before regex matching.

**Impact:**
- CPU exhaustion with crafted input
- Denial of service
- Slow response times

**Recommendation:**
1. Enforce maximum length BEFORE regex matching (currently after)
2. Add regex timeout protection
3. Use compiled regex patterns for performance
4. Consider using simple character whitelisting instead of regex

**Priority:** HIGH"

gh issue create \
  --title "[HIGH] H-7: Error Messages Leak Internal Information" \
  --label "security,high,bug" \
  --body "**File:** \`onepassword_mcp_server/server.py\`
**Lines:** 751-800

**Description:**
Error messages reveal detailed internal information:

\`\`\`python
# Line 751
error_msg = f\"Invalid input parameters: {str(e)}\"

# Line 792
error_msg = f\"Unexpected error retrieving credentials: {str(e)}\"
\`\`\`

**Impact:**
- Information disclosure about internal structure
- Stack traces may leak file paths and logic
- Helps attackers understand the system
- PII or sensitive data in exception messages

**Recommendation:**
1. Return generic error messages to users
2. Log detailed errors server-side only
3. Implement error code system (e.g., ERR001, ERR002)
4. Never include exception details in user-facing messages

**Priority:** HIGH"

# Medium Severity Issues

gh issue create \
  --title "[MEDIUM] M-1: SecureString Memory Clearing Inefficiency" \
  --label "security,medium,enhancement" \
  --body "**File:** \`onepassword_mcp_server/security_hardening.py\`
**Lines:** 208-220

**Description:**
The memory clearing process is inefficient and may be optimized away by the compiler:

\`\`\`python
def _clear_memory(self):
    # Overwrite with random data
    for i in range(len(self._data)):
        self._data[i] = secrets.randbits(8)  # ❌ Slow

    # Overwrite with zeros
    for i in range(len(self._data)):
        self._data[i] = 0
\`\`\`

**Impact:**
- Performance overhead
- Compiler may optimize away the zeroing
- Multiple passes may be overkill or insufficient

**Recommendation:**
1. Use platform-specific secure zero functions (e.g., \`explicit_bzero\`, \`SecureZeroMemory\`)
2. Implement single-pass clearing with cryptographically secure method
3. Consider using \`ctypes\` to access OS-level secure clearing

**Priority:** MEDIUM"

gh issue create \
  --title "[MEDIUM] M-2: Cipher Suite Configuration Without Validation" \
  --label "security,medium,bug" \
  --body "**File:** \`onepassword_mcp_server/security_hardening.py\`
**Lines:** 74-79, 334-335

**Description:**
The code accepts cipher suite configuration but doesn't validate that they're:
1. Actually supported by the system
2. Considered secure by current standards
3. Compatible with the TLS version

\`\`\`python
allowed_cipher_suites: List[str] = field(default_factory=lambda: [
    \"ECDHE-RSA-AES256-GCM-SHA384\",  # ❌ No validation these exist
    \"ECDHE-RSA-AES128-GCM-SHA256\",
    ...
])
\`\`\`

**Impact:**
- Server may fail to start with invalid ciphers
- Weak ciphers may be accepted
- Configuration errors go undetected

**Recommendation:**
1. Validate cipher suites at startup
2. Maintain allowlist of approved modern ciphers
3. Reject known-weak ciphers (DES, RC4, MD5, etc.)
4. Warn about deprecated but currently acceptable ciphers

**Priority:** MEDIUM"

gh issue create \
  --title "[MEDIUM] M-3: Rate Limiting Per Default Client Only" \
  --label "security,medium,enhancement" \
  --body "**File:** \`onepassword_mcp_server/server.py\`
**Lines:** 127-152, 303

**Description:**
Rate limiting uses a default client ID:

\`\`\`python
def is_allowed(self, client_id: str = \"default\") -> Tuple[bool, int]:
\`\`\`

But the code always uses the default:

\`\`\`python
# Line 303
allowed, remaining = self.rate_limiter.is_allowed()  # ❌ No client_id passed
\`\`\`

**Impact:**
- ALL clients share the same rate limit
- No per-user rate limiting
- Easy to bypass by spawning multiple processes
- Cannot track which client is causing load

**Recommendation:**
1. Implement client identification mechanism
2. Use separate rate limits per client
3. Add configuration for global vs per-client limits
4. Consider IP-based or session-based limiting

**Priority:** MEDIUM"

gh issue create \
  --title "[MEDIUM] M-4: File Permission Check Incomplete" \
  --label "security,medium,bug" \
  --body "**File:** \`onepassword_mcp_server/security_hardening.py\`
**Lines:** 425-431

**Description:**
The file permission check only validates \"others\" readable bit, not group:

\`\`\`python
if stat_info.st_mode & 0o044:  # ❌ Only checks others, not group
    issues.append(f\"Sensitive file '{filename}' is world-readable\")
\`\`\`

**Impact:**
- Files readable by group are not detected
- Files writable by others/group not checked
- Incomplete security validation

**Recommendation:**
1. Check for group readable: \`0o044\` → \`0o066\`
2. Also check writable permissions: \`0o022\`
3. Verify owner is current user
4. Check parent directory permissions

**Priority:** MEDIUM"

gh issue create \
  --title "[MEDIUM] M-5: Missing Input Sanitization for Metadata Fields" \
  --label "security,medium,bug" \
  --body "**File:** \`onepassword_mcp_server/server.py\`
**Lines:** 903-981 (destructive operations)

**Description:**
While item names are validated with regex, optional fields like \`notes\`, \`website_url\` have minimal validation:

\`\`\`python
notes: Optional[str] = Field(None, max_length=2048)  # ❌ No content validation
website_url: Optional[str] = Field(None, max_length=512)  # ❌ No URL validation
\`\`\`

**Impact:**
- Injection attacks possible in notes field
- Invalid URLs accepted
- Potential XSS if notes are rendered in UI
- Database issues with special characters

**Recommendation:**
1. Validate URL format for \`website_url\`
2. Sanitize notes field (remove control characters)
3. Add content-type validation
4. Implement maximum line length for notes

**Priority:** MEDIUM"

gh issue create \
  --title "[MEDIUM] M-6: No Timeout on Destructive Operations" \
  --label "security,medium,enhancement" \
  --body "**File:** \`onepassword_mcp_server/server.py\`
**Lines:** 993-1369

**Description:**
Destructive operations don't have additional timeout or confirmation beyond the simple string check:

\`\`\`python
@validator('confirmation')
def validate_confirmation(cls, v):
    if v != \"DELETE\":  # ❌ Too simple
        raise ValueError(\"Confirmation must be exactly 'DELETE' to proceed\")
    return v
\`\`\`

**Impact:**
- Accidental deletion possible
- No \"cooling off\" period
- No additional verification
- Simple typo protection only

**Recommendation:**
1. Implement two-step confirmation (require typing item name)
2. Add mandatory delay (e.g., 5 seconds) before deletion
3. Send confirmation email/notification
4. Implement \"soft delete\" with recovery period

**Priority:** MEDIUM"

gh issue create \
  --title "[MEDIUM] M-7: Correlation IDs Predictable (UUID4)" \
  --label "security,medium,enhancement" \
  --body "**File:** \`onepassword_mcp_server/structured_logging.py\`
**Lines:** 270, \`server.py\` line 288

**Description:**
Correlation IDs use UUID4 but are predictable within a single process:

\`\`\`python
correlation_id_value = correlation_id_value or str(uuid.uuid4())
\`\`\`

**Impact:**
- Correlation ID collision possible (low probability)
- Request tracking may be confused
- Not suitable for security-sensitive use

**Recommendation:**
1. Use \`secrets.token_hex()\` for cryptographically secure IDs
2. Add process ID and timestamp to ensure uniqueness
3. Consider using UUIDv7 (time-ordered)

**Priority:** MEDIUM"

gh issue create \
  --title "[MEDIUM] M-8: Environment Validation Warnings Not Enforced" \
  --label "security,medium,bug" \
  --body "**File:** \`onepassword_mcp_server/security_hardening.py\`
**Lines:** 408-422

**Description:**
Environment validation issues are collected but only returned as warnings, never enforced:

\`\`\`python
for indicator in debug_indicators:
    value = os.getenv(indicator, \"\").lower()
    if value in [\"1\", \"true\", \"yes\", \"on\", \"development\", \"debug\", \"test\"]:
        issues.append(f\"Debug/development indicator found: {indicator}={value}\")
        # ❌ No enforcement, just warning
\`\`\`

**Impact:**
- Production deployment with debug mode possible
- Security warnings ignored
- No fail-safe mechanism

**Recommendation:**
1. Make validation failures fatal in production mode
2. Add strict mode that enforces all checks
3. Require explicit override flag for warnings
4. Log security validation results prominently

**Priority:** MEDIUM"

gh issue create \
  --title "[MEDIUM] M-9: Weak Token Validation" \
  --label "security,medium,bug" \
  --body "**File:** \`onepassword_mcp_server/config.py\`
**Lines:** 192-196

**Description:**
Service account token validation is minimal:

\`\`\`python
if len(self.service_account_token) < self.security.token_min_length:
    raise ValueError(f\"Service account token must be at least {self.security.token_min_length} characters\")

if not self.service_account_token.startswith(self.security.token_prefix):
    logging.warning(f\"Service account token does not start with expected prefix '{self.security.token_prefix}'\")
    # ❌ Only a warning, not an error
\`\`\`

**Impact:**
- Invalid tokens accepted
- Typos in configuration not caught early
- Delayed failure at API call time

**Recommendation:**
1. Make prefix check required, not optional
2. Validate token format (e.g., base64, specific structure)
3. Add checksum validation if available
4. Test token validity at startup

**Priority:** MEDIUM"

gh issue create \
  --title "[MEDIUM] M-10: Missing Security Headers Documentation" \
  --label "security,medium,enhancement,documentation" \
  --body "**File:** \`onepassword_mcp_server/security_hardening.py\`
**Lines:** 435-445

**Description:**
Security headers are defined but never actually used in the server:

\`\`\`python
def get_security_headers(self) -> Dict[str, str]:
    return {
        \"Strict-Transport-Security\": \"max-age=31536000; includeSubDomains\",
        # ... etc
    }
    # ❌ Never called or applied
\`\`\`

**Impact:**
- Security headers not applied to responses
- Missing CORS protection
- No XSS protection
- Dead code

**Recommendation:**
1. Implement middleware to apply security headers
2. Document which headers apply to which transport
3. Remove unused code or implement fully
4. Add CSP configuration

**Priority:** MEDIUM"

# Low Severity Issues

gh issue create \
  --title "[LOW] L-1: Metrics Leak Internal Topology" \
  --label "security,low,enhancement" \
  --body "**File:** \`onepassword_mcp_server/server.py\`
**Lines:** 869-898

**Description:**
Metrics expose detailed internal information without authentication:

\`\`\`python
async def get_metrics_impl() -> Dict[str, Any]:
    # Returns all metrics without auth check
    dashboard_data = await dashboard.get_dashboard_data()
\`\`\`

**Impact:**
- Information disclosure about system performance
- Reveals request patterns and usage
- Could aid in timing attacks

**Recommendation:**
1. Add authentication to metrics endpoint
2. Provide different metrics for different roles
3. Sanitize metric names to avoid leaking internals
4. Add configuration for metrics visibility

**Priority:** LOW"

gh issue create \
  --title "[LOW] L-2: Hardcoded Credential Lifetime" \
  --label "security,low,enhancement" \
  --body "**File:** \`onepassword_mcp_server/security_hardening.py\`
**Lines:** 69, 176

**Description:**
Credential maximum lifetime is hardcoded:

\`\`\`python
credential_max_lifetime_seconds: int = 300  # 5 minutes
# ...
self._max_lifetime = 300  # 5 minutes default
\`\`\`

**Impact:**
- Cannot adjust based on use case
- May be too long or too short for different scenarios
- Not configurable per credential type

**Recommendation:**
1. Make configurable via environment variable
2. Support per-operation lifetime configuration
3. Add ability to refresh/extend lifetime
4. Document lifetime implications

**Priority:** LOW"

gh issue create \
  --title "[LOW] L-3: Logging Configuration Exposes Debug State" \
  --label "security,low,bug" \
  --body "**File:** \`onepassword_mcp_server/config.py\`
**Lines:** 255-260

**Description:**
The logging configuration accepts any string value and only warns on unknown values:

\`\`\`python
try:
    log_level = LogLevel(log_level_str)
except ValueError:
    logging.warning(f\"Unknown log level '{log_level_str}', defaulting to INFO\")
    log_level = LogLevel.INFO
\`\`\`

**Impact:**
- Misconfiguration silently ignored
- May run in unexpected log level
- Production systems with debug logging

**Recommendation:**
1. Fail fast on invalid log levels in production
2. Add strict mode for configuration validation
3. Validate in CI/CD pipeline
4. Default to WARNING in production, INFO in development

**Priority:** LOW"

gh issue create \
  --title "[LOW] L-4: Circuit Breaker State Change Logging" \
  --label "security,low,enhancement" \
  --body "**File:** \`onepassword_mcp_server/resilience.py\`
**Lines:** 138-154

**Description:**
Circuit breaker state changes log at INFO/WARNING but these are security-relevant events that should be logged at higher severity:

\`\`\`python
def _open_circuit(self):
    self.state = CircuitState.OPEN
    self.stats.circuit_open_count += 1
    logger.warning(\"Circuit breaker opened due to failures\")  # ❌ Should be ERROR
\`\`\`

**Impact:**
- Important security events may be missed
- Alert thresholds may not trigger
- Incident response delayed

**Recommendation:**
1. Log circuit open at ERROR level
2. Log circuit close at WARNING level
3. Add audit logging for state changes
4. Include failure context in logs

**Priority:** LOW"

gh issue create \
  --title "[LOW] L-5: Missing Dependency Version Pinning" \
  --label "security,low,enhancement,dependencies" \
  --body "**File:** \`pyproject.toml\`
**Lines:** 37-42

**Description:**
Dependencies use minimum version constraints only:

\`\`\`toml
dependencies = [
    \"mcp[cli]>=1.6.0\",           # ❌ No upper bound
    \"onepassword-sdk>=0.2.1\",    # ❌ No upper bound
    \"pydantic>=2.5.0\",           # ❌ No upper bound
    \"cryptography>=41.0.0\",      # ❌ No upper bound
]
\`\`\`

**Impact:**
- Breaking changes in dependencies possible
- Security vulnerabilities in newer versions
- Inconsistent builds across environments

**Recommendation:**
1. Use lock file (uv.lock exists - good!)
2. Consider upper bounds for major versions
3. Regular dependency audits
4. Automated dependency updates with testing

**Priority:** LOW"

# Informational Issues

gh issue create \
  --title "[INFO] I-1: Unused CORS Configuration" \
  --label "documentation,informational,cleanup" \
  --body "**File:** \`onepassword_mcp_server/security_hardening.py\`
**Lines:** 97-105, 365-386

**Description:**
CORS configuration exists but MCP server uses stdio transport, not HTTP:

\`\`\`python
# CORS configuration
cors_enabled: bool = True
allowed_origins: List[str] = field(default_factory=lambda: [\"https://localhost\"])
# ...
# ❌ Never used since server uses stdio, not HTTP
\`\`\`

**Impact:**
- Confusing configuration
- Dead code
- May mislead developers

**Recommendation:**
1. Document that CORS is for future HTTP transport
2. Remove if HTTP transport not planned
3. Add feature flag for HTTP transport
4. Update documentation

**Priority:** INFORMATIONAL"

gh issue create \
  --title "[INFO] I-2: Inconsistent Naming Conventions" \
  --label "documentation,informational,cleanup" \
  --body "**File:** Multiple files

**Description:**
Inconsistent naming between \`service_account_token\` and \`OP_SERVICE_ACCOUNT_TOKEN\`:

- Config uses \`service_account_token\`
- Environment uses \`OP_SERVICE_ACCOUNT_TOKEN\`
- Some docs say just \`SERVICE_ACCOUNT_TOKEN\`

**Impact:**
- Confusion for developers
- Documentation inconsistencies
- Potential configuration errors

**Recommendation:**
1. Standardize on one naming convention
2. Update all documentation
3. Consider aliases for backward compatibility

**Priority:** INFORMATIONAL"

gh issue create \
  --title "[INFO] I-3: Missing Rate Limit Headers in Responses" \
  --label "enhancement,informational,ux" \
  --body "**File:** \`onepassword_mcp_server/server.py\`
**Lines:** 127-152

**Description:**
Rate limiting is implemented but clients aren't informed about:
- Current limit
- Remaining requests
- Reset time

**Impact:**
- Clients cannot implement backoff
- Poor user experience
- Unnecessary retry attempts

**Recommendation:**
1. Add rate limit info to response metadata
2. Implement standard rate limit headers (X-RateLimit-*)
3. Document rate limiting behavior
4. Provide retry-after information

**Priority:** INFORMATIONAL"

echo ""
echo "✅ Successfully created 28 GitHub issues from security review findings"
echo ""
echo "Summary:"
echo "  - 3 Critical severity issues"
echo "  - 7 High severity issues"
echo "  - 10 Medium severity issues"
echo "  - 5 Low severity issues"
echo "  - 3 Informational issues"
