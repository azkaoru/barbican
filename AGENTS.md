# Barbican Agent Guidelines

## Build/Lint/Test Commands
- **All tests**: `tox`
- **Unit tests**: `stestr run`
- **Functional tests**: `tox -e functional`
- **Single test**: `stestr run <test_path>` (e.g., `stestr run barbican.tests.api.test_secrets.SecretTestCase.test_create_secret`)
- **Linting**: `tox -e pep8`
- **Security scan**: `tox -e bandit`
- **Type checking**: `pyright`
- **Build docs**: `tox -e docs`

## Code Style Guidelines
- Follow OpenStack Style Commandments (79 char lines, 4-space indent)
- Apache 2.0 license headers on all Python files
- **Imports**: stdlib → third-party → local; one per line; `from barbican import i18n as u`
- **Naming**: UPPER_CASE constants, CamelCase classes, snake_case functions/variables
- **Config/Logger**: `CONF = config.CONF`, `LOG = utils.getLogger(__name__)`
- **Rules**: Use `oslo_` prefix, dict comprehensions, `assertIsNone()` over `assertEqual()`
- **Error Handling**: `pecan.abort()` for HTTP errors, `@handle_exceptions()` decorator
- **Testing**: Unit tests required, use stestr, document feature usage