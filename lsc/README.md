# LSC - Large scale code changes

As we're supporting code on multiple branches at the same time, we need
to support mirroring structural changes from the development branches
into the LTS branches. Changes that address many files, refactoring,
renaming, cleanups and testing should be applied with `task lts` in the
root of the project. Rules should be added to the root taskfile as they
are added.

Think of it as `go fmt`, but rather than cherry-picking the change made
to the `master` branch, we can re-run the LSC rules on LTS.

## Adding a LSC rule

Add rules under lsc/<effort>/Taskfile.yml.
Adjust root Taskfile to include the LSC.

## Running LSC rules

In the root of the project, run `task lsc`.
In a LSC rule subfolder, run `task`.

## Violating a LSC rule

If the code quality degrades over time, LSC rules may be re-run.