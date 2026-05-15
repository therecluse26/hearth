# Hearth Python SDK

Python client for the [Hearth](https://github.com/therecluse26/hearth) identity API.

> **SDK Specification:** This SDK must conform to the [Hearth SDK Common Specification](../../docs/sdk-spec.md).

## Installation

```bash
pip install hearth-sdk
```

## Quick start

```python
from hearth import HearthClient

client = HearthClient(
    issuer_url="https://auth.example.com",
    client_id="my-client",
)
```
