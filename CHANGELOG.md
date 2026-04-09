# Changelog

All notable changes to this project should be documented in this file.

## [Unreleased]

### Changed
- Made framework-specific dependencies optional extras instead of hard dependencies
- Reused a shared `httpx.AsyncClient` and `requests.Session` instead of creating connections per auth check
- Added configurable `auth_timeout` for sync and async HTTP clients
- Added top-level lazy exports for `NewtonAuth` and `AsyncNewtonAuth`
- Added `.gitignore`, Ruff configuration, and pre-commit hooks

### Fixed
- Fixed cookie deletions being silently lost in `newton_protected` and `require_newton_auth` when sessions are invalid
- Fixed cache TTL handling so `client_cache_ttl_seconds=0` expires immediately instead of never expiring
- Wired Django settings through to `AUTH_TIMEOUT`
- Documented FastAPI shutdown cleanup for the shared async client

## [0.1.0]

Initial public release of the backend-only Newton authentication SDK.

### Added
- Django integration
- FastAPI integration
- Signed session and state cookie handling
- Callback assertion decryption and validation
- In-memory bounded LRU auth cache
