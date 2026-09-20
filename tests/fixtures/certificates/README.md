# Test Certificates

This directory holds test certificates for integration tests (currently
empty — fixtures are generated on demand).

**WARNING: These certificates are INSECURE and must NEVER be used in production.**

Generate test certificates with:
```bash
python scripts/utilities/generate_certificate.py
```
The script writes `fullchain.pem`/`privkey.pem` to the platform SSL
dir (`get_ssl_dir()`); copy them here when a fixture is needed, or
generate one in-test via `cryptography.x509` as the existing tests do.
