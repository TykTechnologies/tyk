# StorageDriver

The StorageDriver interface is an abstraction over redis6 and redis7 currently.
New driver implementations can be added, and those need to implement this interface.

The integration test for particular drivers is in `integration_test.go`. It is expected
that new drivers are included here and will pass this test. Run it with `make`.

# Redis drivers

We implement two redis drivers currently:

- `redis6` implements redis <=6 protocol,
- `redis7` implements redis >=7 protocol.

The primary implementation of the redis drivers is as follows:

- `driver.go` - main implementation of StorageDriver (shared),
- `export.go` - type aliases to enable shared code (not shared),
- `redis.go` - per-driver implementation (not shared).

The driver code base takes advantage of type aliases so that local symbols
like `NewRedisClient` point to `v8.NewRedisClient` or `v9` respectively. The
aliased types are defined in `export.go` for redis6 and redis7 packages.

The type aliases allow us to copy `redis6/redis.go` without changes into
the `redis7` package. If you need to edit this file, be sure to run `make`
under `storage/internal` so that it's updated for redis7.

# Implementing a new storage driver

If you're implementing a new storage driver, follow this process:

1. create a subpackage, like `memory` for the driver,
2. update `internal/types.go` to import the driver,
3. add test case in `types_test.go` to run against the new driver,
4. your implementation must pass this tests, match expected behaviour,
5. in `internal/storage`, when `make` passes, your driver is complete.

To pass redis drivers, run `make redis-start` to start both redis6 and 7
instances with docker. The integration test is configured to use them.
