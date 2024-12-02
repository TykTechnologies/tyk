#!/bin/sh

# Run the linting task
echo "Running linter..."
task lint

# Check the exit code of the linting task
if [ $? -ne 0 ]; then
  echo "Linting failed. Commit aborted."
  exit 1
fi

# If linting passes, allow the commit to proceed
exit 0