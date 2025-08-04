# Certificate Expiry Monitor Test Data

This directory contains comprehensive test data for the certificate expiry monitor configuration. Each file name is self-documenting and describes the exact configuration values being tested.

## Test Data Files

### Complete Configuration Tests

#### 1. **cert_monitor_warning_15days_check_30min_event_12hours_workers_10.json**
- **Purpose**: Typical configuration with moderate values
- **Values**: 15 days warning, 30 min check cooldown, 12 hour event cooldown, 10 workers
- **Use Case**: Standard development/testing environment

#### 2. **cert_monitor_warning_1day_check_1sec_event_1sec_workers_1.json**
- **Purpose**: Edge cases with minimum allowed values
- **Values**: 1 day warning, 1 second cooldowns, 1 worker
- **Use Case**: Testing boundary conditions and minimum values

#### 3. **cert_monitor_warning_90days_check_2hours_event_48hours_workers_50.json**
- **Purpose**: High values suitable for production environments
- **Values**: 90 days warning, 2 hour check cooldown, 48 hour event cooldown, 50 workers
- **Use Case**: Large-scale production deployments

#### 4. **cert_monitor_warning_7days_check_15min_event_6hours_workers_5.json**
- **Purpose**: Development/testing configuration
- **Values**: 7 days warning, 15 min check cooldown, 6 hour event cooldown, 5 workers
- **Use Case**: Development and CI/CD environments

#### 5. **cert_monitor_warning_30days_check_1hour_event_24hours_workers_20.json**
- **Purpose**: Typical production configuration (matches defaults)
- **Values**: 30 days warning, 1 hour check cooldown, 24 hour event cooldown, 20 workers
- **Use Case**: Standard production deployments

#### 6. **cert_monitor_warning_3days_check_5min_event_1hour_workers_3.json**
- **Purpose**: High-frequency monitoring configuration
- **Values**: 3 days warning, 5 min check cooldown, 1 hour event cooldown, 3 workers
- **Use Case**: Critical systems requiring frequent monitoring

#### 7. **cert_monitor_warning_60days_check_4hours_event_72hours_workers_30.json**
- **Purpose**: Conservative production configuration
- **Values**: 60 days warning, 4 hour check cooldown, 72 hour event cooldown, 30 workers
- **Use Case**: Large enterprises with conservative security policies

### Partial Configuration Tests

#### 8. **cert_monitor_only_warning_threshold_45days.json**
- **Purpose**: Test default value handling when only warning threshold is specified
- **Values**: 45 days warning, all other values use defaults
- **Use Case**: Testing default value application

#### 9. **cert_monitor_only_check_cooldown_1800sec.json**
- **Purpose**: Test default value handling when only check cooldown is specified
- **Values**: 1800 seconds (30 min) check cooldown, all other values use defaults
- **Use Case**: Testing default value application

#### 10. **cert_monitor_only_event_cooldown_43200sec.json**
- **Purpose**: Test default value handling when only event cooldown is specified
- **Values**: 43200 seconds (12 hours) event cooldown, all other values use defaults
- **Use Case**: Testing default value application

#### 11. **cert_monitor_only_max_workers_100.json**
- **Purpose**: Test default value handling when only max concurrent checks is specified
- **Values**: 100 max workers, all other values use defaults
- **Use Case**: Testing default value application

#### 12. **cert_monitor_warning_and_check_cooldown_only.json**
- **Purpose**: Test default value handling when only warning and check cooldown are specified
- **Values**: 14 days warning, 1200 seconds (20 min) check cooldown, other values use defaults
- **Use Case**: Testing partial configuration scenarios

### Environment Variable Override Tests

#### 13. **cert_monitor_defaults_with_env_overrides.json**
- **Purpose**: Test environment variable overrides taking precedence over config file values
- **Values**: Default values in file, overridden by environment variables in test
- **Use Case**: Testing environment variable precedence

## Default Values

When configuration values are not specified, the following defaults are applied:

- `warning_threshold_days`: 30 days
- `check_cooldown_seconds`: 3600 seconds (1 hour)
- `event_cooldown_seconds`: 86400 seconds (24 hours)
- `max_concurrent_checks`: 20 workers

## Test Coverage

These test data files provide comprehensive coverage for:

1. **Complete Configurations**: All fields specified with various realistic values
2. **Partial Configurations**: Testing default value application
3. **Edge Cases**: Minimum and maximum values
4. **Environment Variables**: Override behavior
5. **Different Use Cases**: Development, testing, production, and enterprise scenarios

## File Naming Convention

All files follow the naming convention:
- `cert_monitor_<description>.json` for input files
- `expect.cert_monitor_<description>.json` for expected output files

The description includes the actual values being tested, making the files self-documenting.

## Usage

These test files are used by the `TestCertificateExpiryMonitorConfig` test in `config_test.go` to verify:

1. Configuration loading from JSON files
2. Default value application for missing fields
3. Environment variable override behavior
4. JSON serialization/deserialization
5. Configuration validation

## Maintenance

When adding new test scenarios:

1. Create both input and expected output files
2. Use descriptive names that include the actual values
3. Update this README with the new scenario description
4. Add the file to the test list in `config_test.go`
5. Ensure the test passes before committing 