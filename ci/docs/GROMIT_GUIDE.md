# Gromit Guide

Gromit is the template generation and policy management tool that produces CI/CD workflows, Dockerfiles, and GoReleaser configurations for Tyk repositories.

## Glossary

| Term | Meaning |
|------|---------|
| `buildenv` | The `tykio/golang-cross` image tag used for cross-compilation (e.g., `1.25-bullseye`) |
| CGO | C-Go interop — binaries that link against C libraries (e.g., gateway, dashboard) |
| PGO | Pure Go — statically linked binaries with no C dependencies (e.g., pump, sink) |
| DHI | Docker Hardened Images — commercially supported base images from Docker with FIPS, SBOM, and provenance attestations |
| `pcrepo` | Packagecloud repository for uploading deb/rpm packages |
| `csrepo` | Cloudsmith Docker registry |
| `cirepo` | ECR (AWS) CI registry for internal builds |
| `dhrepo` | DockerHub registry |
| Feature | A flag that controls which templates get rendered and which builds are included |

## Repository

```
https://github.com/TykTechnologies/gromit
```

## Quick Start

### Clone and set up

```bash
gh repo clone TykTechnologies/gromit /tmp/gromit
cd /tmp/gromit
go build ./...
go test ./policy/...
```

### Generate output for a repo and branch

```bash
go run . policy gen /tmp/output --repo tyk --branch master
go run . policy gen /tmp/output --repo tyk --branch release-5.12
go run . policy gen /tmp/output --repo tyk-analytics --branch master
```

### Create a PR from gromit output

```bash
# 1. Generate the output
go run . policy gen /tmp/output --repo tyk --branch master

# 2. In the target repo, create a branch
cd /path/to/tyk
git checkout -B feat/my-change origin/master

# 3. Copy the generated files
cp /tmp/output/ci/Dockerfile.distroless ci/Dockerfile.distroless
cp /tmp/output/ci/goreleaser/goreleaser.yml ci/goreleaser/goreleaser.yml
cp /tmp/output/.github/workflows/release.yml .github/workflows/release.yml

# 4. Commit and push
git add ci/Dockerfile.distroless ci/goreleaser/goreleaser.yml .github/workflows/release.yml
git commit -m "chore: update gromit-generated files"
git push -u origin feat/my-change

# 5. Create PR
gh pr create --base master --title "chore: update gromit-generated files"
```

## How To

### Update the Go version

The Go version is controlled by `buildenv`. It sets the `tykio/golang-cross` image tag.

**For all repos in a group:**

```yaml
cgo-services:
  buildenv: 1.25-bullseye
```

**For a specific branch only:**

```yaml
branches:
  release-5.12:
    buildenv: 1.25-bullseye
```

**Verify the image exists before committing:**

```bash
docker manifest inspect tykio/golang-cross:1.25-bullseye
```

Then regenerate and confirm:

```bash
go run . policy gen /tmp/check --repo tyk --branch master
grep "golang_cross" /tmp/check/.github/workflows/release.yml
```

### Add a new release branch

Add the branch with its features. Builds are inherited from repo level automatically:

```yaml
release-5.13:
  buildenv: 1.25-bullseye
  features:
    - release-test
    - distroless
    - fips
```

### Enable or disable FIPS for a branch

Add `fips` to the features list to enable, omit it to disable:

```yaml
# FIPS enabled
release-5.12:
  features:
    - release-test
    - distroless
    - fips

# FIPS disabled
release-5.10:
  features:
    - release-test
    - distroless
```

The `fips` build must be defined at repo level with `feature: fips`. It is only included in branches where `fips` is in the features list.

### Override a build for a specific branch

Use case: EE on release-5.12 should use distroless instead of DHI.

```yaml
release-5.12:
  builds:
    ee:
      dockerbaseimage: distroless    # use default distroless base
      archs:
        - go: amd64
          deb: amd64
          docker: linux/amd64
        - go: arm64
          deb: aarch64
          docker: linux/arm64
        - go: s390x
          deb: s390x
          docker: linux/s390x
  features:
    - release-test
    - distroless
    - fips
```

Setting `dockerbaseimage: distroless` tells the template to use the default distroless image rather than the repo-level custom base image. This is a sentinel value — the template checks for it and does not pass `BASE_IMAGE` to Docker.

### Add a new build variant

Example: adding a PAYG build to tyk gateway.

```yaml
# At repo level under tyk.builds:
payg:
  feature: payg                  # only on branches with "payg" in features
  flags:
    - -tags=goplugin,ee,payg
  buildpackagename: tyk-gateway-payg
  pcrepo: tyk-ee-unstable
  dhrepo: tykio/tyk-gateway-payg
  cirepo: tyk-payg
  description: >-
    Tyk Gateway Pay-As-You-Go Edition
  imagetitle: Tyk Gateway PAYG
  archs:
    - go: amd64
      deb: amd64
      docker: linux/amd64
    - go: arm64
      deb: aarch64
      docker: linux/arm64
```

Then add `payg` to the features of branches that need it.

### Change the Docker base image

**For all builds (distroless default):**

```yaml
distrolessbaseimage: base-debian13:latest
```

**For specific builds (DHI override):**

```yaml
ee:
  dockerbaseimage: tykio/dhi-busybox:1.37-fips
```

### Skip Docker for a specific architecture

Use `skipdocker: true`. Packages (.deb/.rpm) are still built.

```yaml
archs:
  - go: s390x
    deb: s390x
    docker: linux/s390x
    skipdocker: true
```

### Add environment variables to a build

```yaml
fips:
  env:
    - GOFIPS140=v1.0.0
```

### Add a new Docker registry for a build

Each build can publish to multiple registries:

| Field | Registry | Example |
|-------|----------|---------|
| `dhrepo` | DockerHub | `tykio/tyk-gateway` |
| `csrepo` | Cloudsmith | `docker.tyk.io/tyk-gateway/tyk-gateway` |
| `cirepo` | ECR (CI) | `tyk` |

Add the field to the build definition. No template changes needed:

```yaml
std:
  dhrepo: tykio/tyk-pump
  csrepo: docker.tyk.io/tyk-pump/tyk-pump    # add this line
```

### Add a new repo to gromit

1. Choose the group: `cgo-services` (needs CGO) or `pgo-services` (pure Go).

2. Add the repo to `config/config.yaml`:

```yaml
pgo-services:
  repos:
    my-new-service:
      binary: my-new-service
      packagename: tyk-my-new-service
      configfile: my-new-service.conf
      versionpackage: github.com/TykTechnologies/my-new-service/version
      builds:
        std:
          buildpackagename: tyk-my-new-service
          pcrepo: tyk-my-new-service-unstable
          dhrepo: tykio/tyk-my-new-service
          cirepo: my-new-service
          description: >-
            My New Service
          imagetitle: Tyk My New Service
          archs:
            - go: amd64
              deb: amd64
              docker: linux/amd64
            - go: arm64
              deb: aarch64
              docker: linux/arm64
      branches:
        master:
          features:
            - release-test
            - distroless
```

3. Generate and verify:

```bash
go run . policy gen /tmp/output --repo my-new-service --branch master
ls /tmp/output/
```

**Checklist:**
- [ ] Packagecloud repos exist
- [ ] DockerHub repo exists
- [ ] ECR repo exists (if using `cirepo`)
- [ ] `versionpackage` matches the Go source
- [ ] `configfile` matches the binary's expected config

### Update the upgrade test version

```yaml
upgradefromver: 5.0.0
```

This sets which old version is installed from the stable packagecloud repo during smoke tests.

## Testing Changes

### Before pushing to gromit

```bash
# 1. Run tests
go test ./policy/... -count=1

# 2. Generate and inspect
go run . policy gen /tmp/output --repo tyk --branch master

# 3. Check key values
grep "golang_cross" /tmp/output/.github/workflows/release.yml
head -5 /tmp/output/ci/Dockerfile.distroless
grep "BASE_IMAGE" /tmp/output/.github/workflows/release.yml

# 4. If your change affects multiple branches, test them all
for branch in master release-5.12 release-5.11; do
  go run . policy gen /tmp/output-$branch --repo tyk --branch $branch
  echo "=== $branch ==="
  grep "golang_cross\|BASE_IMAGE" /tmp/output-$branch/.github/workflows/release.yml
done
```

### After merging to gromit

When changes are merged to gromit's main branch, the `policy sync` command runs automatically. This generates output for every repo and branch, and creates or updates PRs in each target repo.

To run sync manually:

```bash
go run . policy sync --repo tyk        # single repo
go run . policy sync                    # all repos
```

### Verifying changes reached target repos

```bash
gh pr list --repo TykTechnologies/tyk --search "gromit" --state open
```

### Rolling back a bad change

```bash
# Revert in gromit
git revert <commit-sha>
git push

# Sync will create corrective PRs, or run manually:
go run . policy sync --repo tyk
```

## Modifying Templates

Templates live in `policy/templates/<feature>/`. Before editing, understand the blast radius — a template change affects every repo and branch that has the feature enabled.

### Check which repos use a feature

```bash
grep -B10 "features:" config/config.yaml | grep -A10 "<feature-name>"
```

### Test all affected repos after editing

```bash
for repo in tyk tyk-analytics tyk-pump portal; do
  go run . policy gen /tmp/output-$repo --repo $repo --branch master 2>/dev/null
  echo "=== $repo: $(grep -c 'BASE_IMAGE' /tmp/output-$repo/.github/workflows/release.yml 2>/dev/null) BASE_IMAGE refs ==="
done
```

### Common pitfalls

- `{{range}}` changes the dot context — `.` inside a range is the current element. Use `$r := .` before the range to preserve access to the root.
- Adding a field that doesn't exist for all repos causes `missingkey=error` panics.
- YAML is whitespace-sensitive. `{{-` trims preceding whitespace, `-}}` trims following.

### Adding custom workflow steps that survive gromit regeneration

Do not modify generated files. Instead:
- **Preferred**: add the step to the gromit template so it's generated for all repos.
- **Alternative**: create a separate workflow file (e.g., `.github/workflows/custom-tests.yml`) that is not managed by gromit. Generated files are marked with `# Generated by: gromit policy`.

## Debugging

### Template rendering error

```
panic: template: goreleaser.gotmpl:380: unexpected {{end}}
```

Mismatched `{{if}}` / `{{range}}` / `{{end}}` blocks in the template file.

### Output is empty or missing a section

A conditional is evaluating to false. Add temporary debug output to the template:

```
{{/* DEBUG */}} features={{ .Branchvals.Features }}
```

Generate, check the output, then remove the debug line.

### A build variant is missing from generated goreleaser

The build has `feature: <name>` set, and that feature is not in the branch's features list. Check both:

```bash
grep -A2 "feature:" config/config.yaml        # find the required feature
grep -A5 "release-5.12:" config/config.yaml   # check branch features
```

### Branch override doesn't clear a repo-level value

Empty strings don't override in mergo. Use a sentinel value. For example, `dockerbaseimage: distroless` tells the template to use the default:

```
{{- if and $bv.DockerBaseImage (ne $bv.DockerBaseImage "distroless") }}
BASE_IMAGE={{ $bv.DockerBaseImage }}
{{- end }}
```

## Config Structure

The central config is at `config/config.yaml` with a three-level hierarchy:

```
policy:
  groups:
    <group>:                    # e.g., cgo-services, pgo-services
      buildenv: ...             # Group-level defaults
      baseimage: ...
      distrolessbaseimage: ...
      features: [...]
      repos:
        <repo>:                 # e.g., tyk, tyk-analytics
          builds:               # Repo-level build definitions
            std: ...
            ee: ...
            fips: ...
          branches:
            master:             # Branch-level overrides
              features: [...]
```

Values cascade: **group → repo → branch**. Branch-level values override repo-level, which override group-level.

- Most fields: later levels override earlier (empty values do not override)
- **Builds**: branch-level fields merge into repo-level fields for the same build name
- **Features**: unioned across all levels

## Features

Features control which template directories get rendered and provide conditional logic in templates.

| Feature | What it provides |
|---------|-----------------|
| `releng` | Release workflow, goreleaser config, Dockerfile.std, install scripts |
| `distroless` | Dockerfile.distroless (used instead of Dockerfile.std) |
| `release-test` | Smoke tests, upgrade tests in release workflow |
| `fips` | Enables FIPS build variants (builds with `feature: fips`) |
| `nightly-e2e` | Nightly end-to-end test workflow |
| `el7-pgo-build` | Legacy EL7 build support |
| `ai-studio-frontend-build` | Frontend build step for AI Studio |
| `default-distros` | Uses hardcoded distro list instead of TUI service |

## Template Structure

```
policy/templates/
├── distroless/           # Feature: distroless
│   └── ci/Dockerfile.distroless
├── releng/               # Feature: releng
│   ├── ci/
│   │   ├── Dockerfile.std
│   │   └── goreleaser/goreleaser.yml
│   └── .github/workflows/
│       ├── release.yml
│       └── release.yml.d/        # Sub-templates
│           ├── goreleaser.gotmpl
│           ├── smoke-tests.gotmpl
│           └── ...
├── subtemplates/         # Available to ALL templates
│   └── goreleaser.yml.d/
│       ├── builds.gotmpl
│       ├── nfpm.gotmpl
│       └── ...
├── nightly-e2e/
├── el7-pgo-build/
└── test-square/
```

Templates use Go `text/template` with Sprig functions.

## Generated Files

These files are marked with `# Generated by: gromit policy`. Never edit them directly.

| File | Feature |
|------|---------|
| `ci/Dockerfile.distroless` | distroless |
| `ci/Dockerfile.std` | releng |
| `ci/goreleaser/goreleaser.yml` | releng |
| `.github/workflows/release.yml` | releng |
| `ci/bin/pc.sh` | releng |
| `ci/bin/unlock-agent.sh` | releng |
| `ci/install/*.sh` | releng |

## Managed Repos

| Repo | Group | CGO | FIPS | Branches |
|------|-------|-----|------|----------|
| tyk | cgo-services | Yes | Yes | master, release-5.8 through 5.12 |
| tyk-analytics | cgo-services | Yes | Yes | master, release-5.8 through 5.12 |
| portal | cgo-services | Yes | Yes | master |
| ai-studio | cgo-services | Yes | No | main |
| tyk-pump | pgo-services | No | Yes | master |
| tyk-sink | pgo-services | No | Yes | master |
| tyk-identity-broker | pgo-services | No | No | master |

**Not managed by gromit:** tyk-operator-internal, midsommar

## Reference: Build Fields

| Field | Purpose | Example |
|-------|---------|---------|
| `flags` | Go build flags | `["-tags=goplugin,ee"]` |
| `buildpackagename` | Package name for deb/rpm | `tyk-gateway-ee` |
| `dockerbaseimage` | Docker base image override | `tykio/dhi-busybox:1.37-fips` |
| `feature` | Feature gate for this build | `fips` |
| `pcrepo` | Packagecloud repo for uploads | `tyk-ee-unstable` |
| `upgraderepo` | Packagecloud repo for upgrade tests | `tyk-gateway` |
| `dhrepo` | DockerHub image name | `tykio/tyk-gateway-ee` |
| `csrepo` | Cloudsmith image name | `docker.tyk.io/tyk-gateway/tyk-gateway-ee` |
| `cirepo` | ECR CI repo name | `tyk-ee` |
| `description` | OCI image description | |
| `imagetitle` | OCI image title | |
| `env` | Build environment variables | `["GOFIPS140=v1.0.0"]` |
| `archs` | Target architectures | |

## Reference: Arch Fields

| Field | Purpose | Example |
|-------|---------|---------|
| `go` | GOARCH value | `amd64` |
| `deb` | Debian arch name | `aarch64` |
| `docker` | Docker platform | `linux/arm64` |
| `skipdocker` | Skip Docker image for this arch | `true` |

## Reference: Template Variables

| Variable | Description |
|----------|-------------|
| `.Name` | Repo name |
| `.Branch` | Branch name |
| `.Binary` | Binary name |
| `.PackageName` | Package name |
| `.Branchvals.Buildenv` | Go cross-compile image tag |
| `.Branchvals.BaseImage` | Debian base for deb stage |
| `.Branchvals.DistrolessBaseImage` | Distroless base image |
| `.Branchvals.Features` | Active features |
| `.Branchvals.Builds` | Build variants |
| `.Branchvals.Cgo` | CGO enabled |
| `.Branchvals.ConfigFile` | App config filename |

## Reference: Template Functions

| Function | Description |
|----------|-------------|
| `GetDockerBuilds` | Returns builds with Docker registry configs |
| `GetDockerPlatforms` | Returns Docker platforms (respects `skipdocker`) |
| `GetCC target host` | Returns cross-compiler name |
| `GetImages "DHRepo" "CSRepo"` | Returns image names for given registries |
| `HasBuild "fips"` | Checks if a build exists |
| `has "feature" .Features` | Checks if a feature is active (Sprig) |
