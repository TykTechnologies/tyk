# internal

This location has a Taskfile.yml with common actions.
Please run `task` and inspect available options.

Goals for the package:

- organize source code similarly to the stdlib
- share source code folder for all LTS releases
- compatibility with oldest LTS release Go version
- *no modern third party deps*

Make sure `task test` passes for newly added code.
If you can, cover the code with a test.
