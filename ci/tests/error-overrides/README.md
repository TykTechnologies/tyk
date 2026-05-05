# Error Overrides Tests

This directory contains CI tests for the `error_overrides` feature.

## Overview

Tests the error override functionality that allows customizing error responses.

## Structure

```
error-overrides/
├── apps/               # API definitions for testing
├── configs/            # Gateway configuration files
│   ├── tyk.conf       # Gateway config with error_overrides enabled
│   └── nginx-ok.conf  # Backend nginx configuration
├── policies/           # Policy definitions
├── scripts/            # Test execution scripts
│   └── run-override-tests.sh
├── docker-compose.yml  # Test environment setup
├── test.sh            # CI entrypoint
└── README.md          # This file
```

## Running Tests

### In CI

The `test.sh` script is automatically discovered and run by the `ci-tests` job in `.github/workflows/release-tests.yml`.

```bash
# CI sets GATEWAY_IMAGE environment variable
export GATEWAY_IMAGE=<ecr-registry>/tyk:sha-<commit>
./test.sh
```

### Locally

```bash
cd ci/tests/error-overrides

# Use a specific gateway image
export TYK_GATEWAY_IMAGE=tykio/tyk-gateway:v5.3
./test.sh

# Or use default
./test.sh
```

## Test Coverage

The override tests verify error overrides for error classifications flag match:
- **4xx Errors**: AMF, AKI, RLT, QEX, BTL, CLM, BIV, IHD, TKI, TKE, EAD
- **5xx Errors**: TLE, TLI, TLM, TLN, TLH, TLP, UCF, URT, URR, UPE, DNS, NRH
- **Other**: CBO, NHU, CDC

Each test verifies:
1. Response body contains expected override content
2. Response headers include custom error flags
3. Response status code is overridden correctly
4. Access logs contain the correct response_flag

## Configuration

The `error_overrides` configuration in `tyk.conf` maps status codes and flags to custom responses:

```json
{
  "error_overrides": {
    "429": [
      {
        "match": {"flag": "RLT"},
        "response": {
          "status_code": 429,
          "body": "{\"error\": \"rate_limit_exceeded\", ...}",
          "headers": {
            "X-Error-Flag": "RLT",
            "Retry-After": "60"
          }
        }
      }
    ]
  }
}
```

## Environment Variables

- `TYK_GATEWAY_IMAGE` - Gateway Docker image to test (default: `tykio/tyk-gateway:latest`)
- `GATEWAY_IMAGE` - Alternative name for gateway image (used in CI)
