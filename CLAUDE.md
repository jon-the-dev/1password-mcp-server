# CLAUDE.md - AI Assistant Development Guide

This document provides comprehensive guidance for AI assistants (like Claude) working on the 1Password MCP Server codebase.

## Project Overview

**Name**: 1Password MCP Server
**Version**: 1.1.0
**Language**: Python 3.12+
**License**: MIT
**Purpose**: A production-ready MCP (Model Context Protocol) server that provides secure access to 1Password credentials for AI assistants with enterprise-grade security, resilience, and monitoring.

### Key Features

- Secure credential retrieval from 1Password via service accounts
- Enterprise-grade security hardening (memory protection, TLS enforcement, request signing)
- Resilience patterns (circuit breaker, retry logic with exponential backoff)
- Comprehensive structured logging with correlation IDs and PII scrubbing
- Health monitoring and operational metrics
- Full MCP protocol compliance with tool discovery
- Rate limiting and input validation
- Audit logging for security events

## Repository Structure

```
1password-mcp-server/
├── onepassword_mcp_server/          # Main Python package
│   ├── __init__.py                  # Package initialization and metadata
│   ├── server.py                    # Main MCP server implementation (1,542 lines)
│   ├── config.py                    # Configuration management and validation
│   ├── security_hardening.py        # Security features (memory protection, TLS, signing)
│   ├── resilience.py                # Circuit breaker and retry logic
│   ├── structured_logging.py        # JSON logging with correlation IDs
│   ├── monitoring.py                # Health checks and metrics collection
│   ├── mcp_protocol_compliance.py   # MCP protocol implementation
│   ├── test_p1_features.py          # Integration tests for P1 features
│   └── test_unit.py                 # Unit tests
├── docs/                            # Comprehensive documentation
│   ├── index.md                     # Documentation home
│   ├── getting-started.md           # Quick start guide
│   ├── DEVELOPER_GUIDE.md           # Developer documentation
│   ├── API_REFERENCE.md             # API documentation
│   ├── SECURITY_GUIDE.md            # Security documentation
│   ├── SETUP_GUIDE.md               # Setup instructions
│   └── TROUBLESHOOTING.md           # Troubleshooting guide
├── pyproject.toml                   # Python project configuration (hatchling)
├── uv.lock                          # UV package manager lockfile
├── Pipfile / Pipfile.lock           # Pipenv configuration (legacy)
├── mkdocs.yml                       # MkDocs documentation configuration
├── README.md                        # Project README
├── SECURITY.md                      # Security policy
├── LICENSE                          # MIT License
└── test_structure.py                # Repository structure tests

```

## Architecture Overview

### Core Components

1. **Server (`server.py`)** - Main MCP server with tool handlers
2. **Configuration (`config.py`)** - Environment-based configuration management
3. **Security (`security_hardening.py`)** - Memory protection, TLS, request signing
4. **Resilience (`resilience.py`)** - Circuit breaker, retry, timeout handling
5. **Logging (`structured_logging.py`)** - JSON logging with PII scrubbing
6. **Monitoring (`monitoring.py`)** - Health checks, metrics, operational dashboard
7. **MCP Protocol (`mcp_protocol_compliance.py`)** - Protocol compliance and tool metadata

### Design Patterns

- **Circuit Breaker Pattern**: Prevents cascading failures to 1Password API
- **Retry with Exponential Backoff**: Handles transient failures gracefully
- **Context Managers**: Automatic resource cleanup (memory, correlation IDs)
- **Dependency Injection**: Configuration passed to components
- **Dataclass Configuration**: Type-safe configuration with validation
- **Event-Driven Logging**: Structured event emission with correlation

### Data Flow

```
AI Assistant → MCP Server → OnePasswordSecureClient → 1Password SDK → 1Password API
                    ↓
              Rate Limiter → Circuit Breaker → Retry Logic → Logging & Metrics
```

## Development Environment Setup

### Prerequisites

- Python 3.12 or higher
- `uv` package manager (recommended) or `pip`
- 1Password account with service account access
- 1Password CLI (optional, for testing)

### Installation

```bash
# Clone the repository
git clone https://github.com/jon-the-dev/1password-mcp-server.git
cd 1password-mcp-server

# Install dependencies using uv (recommended)
uv sync

# Or using pip
pip install -e ".[dev]"

# Set up environment variables
cp .env.example .env
# Edit .env with your OP_SERVICE_ACCOUNT_TOKEN
```

### Running the Server

```bash
# For development with enhanced logging
export LOG_LEVEL=DEBUG
export ENVIRONMENT=development

# Run the server directly
python onepassword_mcp_server/server.py

# Or via installed command
onepassword-mcp-server
```

### Running Tests

```bash
# Run P1 feature tests
python onepassword_mcp_server/test_p1_features.py

# Run unit tests (requires pytest)
pytest onepassword_mcp_server/test_unit.py

# Run repository structure tests
python test_structure.py
```

## Code Organization

### Main Server (`server.py`)

**Key Classes**:
- `OnePasswordSecureClient` - Secure wrapper for 1Password SDK with resilience
- `RateLimiter` - Rate limiting with metrics integration
- `CredentialRequest` - Validated credential request model (Pydantic)
- `CreateCredentialRequest`, `UpdateCredentialRequest`, `DeleteCredentialRequest` - P3 destructive operations

**MCP Tools**:
1. `get_1password_credentials(item_name, vault)` - Retrieve credentials
2. `get_health_status()` - Server health status
3. `get_metrics()` - Operational metrics
4. `get_security_status()` - Security hardening status
5. `create_1password_credential(...)` - Create credential (destructive, disabled by default)
6. `update_1password_credential(...)` - Update credential (destructive, disabled by default)
7. `delete_1password_credential(...)` - Delete credential (destructive, disabled by default)

**Global State**:
- `config` - Server configuration (loaded at startup)
- `logger` - Structured logger instance
- `metrics_collector` - Metrics collection system
- `health_checker` - Health check orchestrator
- `security_manager` - Security hardening manager
- `protocol_manager` - MCP protocol manager
- `secure_client` - 1Password client instance

### Configuration (`config.py`)

**Configuration Classes** (all use `@dataclass`):
- `ServerConfig` - Root configuration
- `RateLimitConfig` - Rate limiting settings
- `CircuitBreakerConfig` - Circuit breaker settings
- `RetryConfig` - Retry logic settings
- `SecurityConfig` - Security policy settings
- `FeatureFlagsConfig` - Feature toggles
- `LoggingConfig` - Logging settings

**Environment Variables**:
- `OP_SERVICE_ACCOUNT_TOKEN` (required) - 1Password service account token
- `ENVIRONMENT` - Deployment environment (development/staging/production)
- `LOG_LEVEL` - Logging level (DEBUG/INFO/WARNING/ERROR/CRITICAL)
- `LOG_FORMAT` - Log format (json/text)
- `RATE_LIMIT_MAX_REQUESTS` - Rate limit threshold
- `CIRCUIT_BREAKER_FAILURE_THRESHOLD` - Circuit breaker threshold
- `DESTRUCTIVE_ACTIONS` - Enable destructive operations (default: false)

### Security Hardening (`security_hardening.py`)

**Key Components**:
- `SecureString` - Memory-protected string with automatic cleanup
- `MemoryProtectionManager` - Secure memory allocation tracking
- `RequestSigningManager` - HMAC-based request integrity
- `TransportSecurityManager` - TLS enforcement and cipher configuration
- `EnvironmentValidator` - Security posture assessment
- `SecurityHardeningManager` - Orchestrates all security features

**Security Features**:
- Memory protection with automatic zeroing on cleanup
- Request signing with SHA-256 HMAC
- TLS 1.2+ enforcement
- Environment security validation
- Active allocation tracking

### Resilience (`resilience.py`)

**Core Classes**:
- `CircuitBreaker` - State machine (closed → open → half-open)
- `RetryManager` - Exponential backoff with jitter
- `ResilientOperationManager` - Combines circuit breaker + retry + timeout

**Circuit Breaker States**:
- `CLOSED` - Normal operation
- `OPEN` - Failing, rejecting requests
- `HALF_OPEN` - Testing recovery

**Error Classification**:
- `RetryableError` - Transient failures (network, timeout)
- `NonRetryableError` - Permanent failures (validation, auth)
- `CircuitBreakerOpenError` - Service unavailable

### Logging (`structured_logging.py`)

**Key Features**:
- JSON structured logging
- Correlation ID propagation via context vars
- Automatic PII/credential scrubbing
- Performance timing with context managers
- Event type categorization (AUDIT, SECURITY, PERFORMANCE, ERROR, ACCESS)

**Usage Pattern**:
```python
with CorrelationContext(correlation_id):
    with PerformanceTimer(logger, "operation", **metadata):
        logger.audit("Operation started", operation="operation_name", **details)
        # ... operation logic ...
```

### Monitoring (`monitoring.py`)

**Components**:
- `MetricsCollector` - Collects counters, gauges, histograms
- `HealthChecker` - Orchestrates health checks
- `OperationalDashboard` - Combines health + metrics

**Metrics Types**:
- **Counters**: Total requests, errors, rate limit rejections
- **Gauges**: Circuit breaker state, uptime, active allocations
- **Histograms**: Request duration, percentiles (p50, p95, p99)

**Health Checks**:
- `basic` - Basic system health
- `onepassword_connectivity` - 1Password API connectivity
- `security_status` - Security hardening status
- `environment_security` - Environment validation

## Development Workflows

### Adding a New MCP Tool

1. **Define the implementation function** in `server.py`:
   ```python
   async def my_new_tool_impl(param1: str, param2: int) -> Dict[str, Any]:
       """Implementation with comprehensive error handling"""
       # Validate inputs
       # Perform operation
       # Log events
       # Return results
   ```

2. **Register in `main()`**:
   ```python
   @mcp.tool()
   async def my_new_tool(param1: str, param2: int) -> Dict[str, Any]:
       """Tool docstring (shown to AI assistants)"""
       return await my_new_tool_impl(param1, param2)
   ```

3. **Add tool metadata** in `register_tool_metadata()`:
   ```python
   tool = ToolMetadata(
       name="my_new_tool",
       description="Tool description",
       parameters={...},
       category="monitoring",  # or "security"
       version="1.1.0",
       # ... other metadata
   )
   protocol_manager.register_tool(tool, None)
   ```

4. **Add tests** in `test_unit.py` or `test_p1_features.py`

### Adding Configuration Options

1. **Add to configuration dataclass** in `config.py`:
   ```python
   @dataclass
   class MyNewConfig:
       setting_name: str = "default_value"

       def __post_init__(self):
           # Validation logic
   ```

2. **Add to `ServerConfig`**:
   ```python
   @dataclass
   class ServerConfig:
       # ... existing fields
       my_new_config: MyNewConfig = field(default_factory=MyNewConfig)
   ```

3. **Add environment variable mapping** in `ConfigLoader.load_from_environment()`:
   ```python
   my_new_config = MyNewConfig(
       setting_name=os.getenv("MY_SETTING_NAME", "default")
   )
   ```

4. **Update `.env.example`** and **README.md** with new variable

### Adding Security Features

1. **Implement in `security_hardening.py`** following existing patterns
2. **Integrate into `SecurityHardeningManager`**
3. **Add health check** in `server.py` if applicable
4. **Add metrics** for the new feature
5. **Update `SECURITY.md`** documentation

### Error Handling Patterns

**Always use this pattern for MCP tool implementations**:

```python
async def tool_impl(param: str) -> Dict[str, Any]:
    start_time = time.perf_counter()
    metrics_collector.increment_counter("server_requests_total")

    try:
        # Validate inputs
        request = RequestModel(param=param)

        # Log operation start
        logger.audit("Operation started", operation="tool_name", param=param)

        # Perform operation with resilience
        result = await resilient_operation()

        # Record success metrics
        duration_ms = (time.perf_counter() - start_time) * 1000
        metrics_collector.record_histogram("request_duration_ms", duration_ms)

        return result

    except (PydanticValidationError, ValidationError) as e:
        # Handle validation errors
        duration_ms = (time.perf_counter() - start_time) * 1000
        metrics_collector.increment_counter("server_errors_total")
        logger.warning("Validation error", error_code="validation_error", duration_ms=duration_ms)
        raise ValueError(f"Invalid input: {str(e)}")

    except CircuitBreakerOpenError:
        # Handle circuit breaker
        metrics_collector.increment_counter("server_errors_total")
        logger.error("Circuit breaker open", error_code="circuit_breaker_open")
        raise ValueError("Service temporarily unavailable")

    except Exception as e:
        # Handle unexpected errors
        metrics_collector.increment_counter("server_errors_total")
        logger.error("Unexpected error", error_code="unexpected_error", metadata={"error": str(e)})
        raise ValueError(f"Operation failed: {str(e)}")
```

## Key Conventions

### Code Style

- **Type Hints**: Use type hints for all function signatures
- **Docstrings**: Use Google-style docstrings for all public functions/classes
- **Naming**:
  - Classes: `PascalCase`
  - Functions/methods: `snake_case`
  - Constants: `UPPER_SNAKE_CASE`
  - Private members: `_leading_underscore`
- **Line Length**: 100 characters (soft limit), 120 (hard limit)
- **Imports**: Standard library → Third-party → Local modules

### Async/Await

- All MCP tool handlers must be `async def`
- Use `await` for all 1Password SDK calls
- Use `asyncio.run()` only in `main()`
- Health checks are async functions

### Logging Conventions

**Log Levels**:
- `logger.debug()` - Development/debugging information
- `logger.info()` - Normal operational events
- `logger.warning()` - Unexpected but handled situations
- `logger.error()` - Error conditions requiring attention
- `logger.critical()` - Critical failures requiring immediate action
- `logger.audit()` - Security-relevant events (credential access)
- `logger.security()` - Security violations (rate limits, auth failures)
- `logger.access()` - Request/response logging
- `logger.performance()` - Performance metrics

**Never log**:
- Raw passwords or credentials
- Full tokens (use `scrub_sensitive_data()`)
- PII without scrubbing

### Validation

- Use Pydantic models for all request validation
- Add `@validator` decorators for custom validation
- Regex patterns for item/vault names: `^[a-zA-Z0-9._-]+$`
- Maximum item name length: 64 characters
- Always validate service account token format

### Testing

- Unit tests for individual components
- Integration tests for P1 features
- Mock 1Password SDK in tests
- Test error conditions and edge cases
- Verify metrics are recorded
- Check logging output

## Security Considerations

### Critical Security Rules

1. **NEVER log plaintext credentials** - Use PII scrubbing
2. **ALWAYS validate input** - Use Pydantic models
3. **ALWAYS use rate limiting** - Prevent abuse
4. **ALWAYS use circuit breaker** - Protect 1Password API
5. **ALWAYS log security events** - Audit trail for compliance
6. **NEVER skip authentication** - Validate service account token
7. **ALWAYS use TLS in production** - Enable `tls_enforcement_enabled`

### Destructive Operations

- **DISABLED BY DEFAULT** - Require `DESTRUCTIVE_ACTIONS=true`
- **ALWAYS require confirmation** - Explicit user confirmation
- **ALWAYS log at CRITICAL level** - Maximum visibility
- **ALWAYS increment metrics** - Track destructive operation attempts
- **NOTE**: Currently placeholders - real implementation requires 1Password CLI/Connect API

### Memory Protection

- Use `SecureString` for credential handling when possible
- Use context managers for automatic cleanup
- Track active allocations for debugging
- Zero memory on cleanup

## Common Tasks

### Debugging Connection Issues

```bash
# Enable debug logging
export LOG_LEVEL=DEBUG

# Test 1Password connectivity
python -c "
import asyncio
from onepassword_mcp_server.monitoring import onepassword_connectivity_check
print(asyncio.run(onepassword_connectivity_check()))
"
```

### Testing Configuration

```bash
# Load and validate configuration
python -c "
from onepassword_mcp_server.config import ConfigLoader
config = ConfigLoader.load_from_environment()
print(ConfigLoader.get_configuration_summary(config))
"
```

### Viewing Metrics

Use the `get_metrics` MCP tool or access programmatically:

```python
from onepassword_mcp_server.monitoring import MetricsCollector

collector = MetricsCollector()
print(collector.get_all_metrics())
```

### Checking Health Status

```bash
# Via MCP tool
# AI Assistant: "Check the health status of the 1Password server"

# Or programmatically
python -c "
import asyncio
from onepassword_mcp_server.monitoring import basic_health_check
print(asyncio.run(basic_health_check()))
"
```

## Dependencies

### Core Dependencies (from `pyproject.toml`)

- `mcp[cli]>=1.6.0` - Model Context Protocol SDK
- `onepassword-sdk>=0.2.1` - 1Password Python SDK
- `pydantic>=2.5.0` - Data validation
- `cryptography>=41.0.0` - Security primitives

### Development Dependencies

- `pytest>=7.0.0` - Testing framework
- `pytest-asyncio>=0.21.0` - Async test support
- `pytest-cov>=4.0.0` - Coverage reporting
- `mypy>=1.5.0` - Static type checking
- `ruff>=0.1.0` - Fast Python linter
- `black>=23.0.0` - Code formatter

### Documentation Dependencies

- `mkdocs>=1.5.0` - Documentation generator
- `mkdocs-material>=9.4.0` - Material theme
- `pymdown-extensions>=10.0.0` - Markdown extensions

## Package Management

This project uses **UV** (recommended) or **pip**:

```bash
# UV (fast, modern)
uv sync                    # Install dependencies
uv add package-name        # Add new dependency
uv remove package-name     # Remove dependency

# Pip (traditional)
pip install -e .           # Install in editable mode
pip install -e ".[dev]"    # Install with dev dependencies
```

## Building and Distribution

```bash
# Build the package
python -m build

# Install locally
pip install -e .

# Publish to PyPI (maintainers only)
python -m twine upload dist/*
```

## MCP Protocol Compliance

### Tool Discovery

The server implements full MCP tool discovery via `ToolMetadata`:
- Tool descriptions and parameters
- Category, tags, version
- Security level and audit requirements
- Example usage and related tools

### Resource Exposure

Resources are exposed via `ResourceMetadata` for:
- Credential items
- Vault information
- Health status
- Metrics data

### Prompt Templates

Pre-built prompt templates via `PromptTemplate` for:
- Common credential operations
- Health monitoring
- Security status checks

## Troubleshooting Guide

### Common Issues

**Issue**: `ConfigurationError: OP_SERVICE_ACCOUNT_TOKEN environment variable is required`
**Solution**: Set the environment variable with your 1Password service account token

**Issue**: `Rate limit exceeded`
**Solution**: Wait for rate limit window to reset or adjust `RATE_LIMIT_MAX_REQUESTS`

**Issue**: `Circuit breaker is open`
**Solution**: Wait for recovery timeout (default 60s) or check 1Password API status

**Issue**: `Item not found in vault`
**Solution**: Verify item name, vault name, and service account permissions

**Issue**: `Destructive actions disabled`
**Solution**: Set `DESTRUCTIVE_ACTIONS=true` environment variable (only if needed)

### Debug Checklist

1. Check environment variables are set correctly
2. Verify service account token is valid and has permissions
3. Check 1Password vault and item names match exactly
4. Review logs with `LOG_LEVEL=DEBUG`
5. Check circuit breaker state in health status
6. Verify rate limit settings
7. Test 1Password connectivity with health check

## Contributing Guidelines

1. **Read** `SECURITY.md` before making security-related changes
2. **Follow** existing code patterns and conventions
3. **Add tests** for all new functionality
4. **Update documentation** in relevant files
5. **Run tests** before committing: `pytest`
6. **Check types** with mypy: `mypy onepassword_mcp_server/`
7. **Format code** with black: `black onepassword_mcp_server/`
8. **Lint code** with ruff: `ruff check onepassword_mcp_server/`

## Release Process

1. Update version in `pyproject.toml` and `__init__.py`
2. Update `CHANGELOG.md` (if exists)
3. Run full test suite
4. Build package: `python -m build`
5. Tag release: `git tag v1.x.x`
6. Push to GitHub: `git push --tags`
7. Publish to PyPI: `python -m twine upload dist/*`

## Additional Resources

- **README.md** - Quick start and feature overview
- **docs/DEVELOPER_GUIDE.md** - Detailed architecture documentation
- **docs/API_REFERENCE.md** - Complete API documentation
- **docs/SECURITY_GUIDE.md** - Security best practices
- **docs/TROUBLESHOOTING.md** - Common issues and solutions
- **SECURITY.md** - Security policy and reporting
- **GitHub Repository**: https://github.com/jon-the-dev/1password-mcp-server
- **Documentation Site**: https://jon-the-dev.github.io/1password-mcp-server/

## Quick Reference

### File Locations

- **Main server**: `onepassword_mcp_server/server.py`
- **Configuration**: `onepassword_mcp_server/config.py`
- **Security**: `onepassword_mcp_server/security_hardening.py`
- **Resilience**: `onepassword_mcp_server/resilience.py`
- **Logging**: `onepassword_mcp_server/structured_logging.py`
- **Monitoring**: `onepassword_mcp_server/monitoring.py`
- **MCP Protocol**: `onepassword_mcp_server/mcp_protocol_compliance.py`
- **Tests**: `onepassword_mcp_server/test_*.py`

### Important Line Numbers (server.py)

- Server initialization: Line 443-532
- Main MCP server setup: Line 1372-1539
- Credential retrieval: Line 697-800
- Health status: Line 803-829
- Metrics collection: Line 869-898
- Destructive operations: Line 993-1369 (disabled by default)

### Key Functions to Know

- `initialize_server()` - Initialize all components (Line 443)
- `get_1password_credentials_impl()` - Main credential retrieval (Line 697)
- `get_health_status()` - Health check endpoint (Line 803)
- `get_metrics_impl()` - Metrics endpoint (Line 869)
- `OnePasswordSecureClient.get_credentials()` - Core credential logic (Line 284)

---

**Version**: 1.1.0
**Last Updated**: 2024-11-18
**Maintained by**: 1Password MCP Server Contributors
