# Regression tests

This is an area for tests that replicate demonstratable issues.

Any test should follow the following convention:

- The name of the test file: `issue_<jira-id>_test.go`
- The name of the test function: `Test_Issue<jira-id>`
- Any test data required for the test: `testdata/issue-<jira-id>-<type>.<ext>`
- Additional files: `regression_test.go` - containing shared utilities for tests
