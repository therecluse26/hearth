# Hearth Python SDK

Python client for the [Hearth](https://github.com/therecluse26/hearth) identity API.

**SDK Specification:** [docs/sdk-spec.md](../../docs/sdk-spec.md)

## Installation

```bash
pip install hearth-sdk
```

## Quick start

```python
from hearth import HearthClient

client = HearthClient(
    issuer_url="https://hearth.example.com",
    client_id="<your-client-id>",
)
```

See the [SDK specification](../../docs/sdk-spec.md) for the full API contract, error taxonomy, middleware requirements, and security requirements.
