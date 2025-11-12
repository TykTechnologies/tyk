# Phase 1 Findings: github-actions Repository Analysis

## Date: 2025-11-05

## Summary

Analyzed the `TykTechnologies/github-actions` repository (located at `~/works/github-actions`) to understand current dashboard image handling and determine required modifications.

---

## Key Actions Analyzed

### 1. `env-up` Action

**Location:** `.github/actions/tests/env-up/action.yaml`

#### Current Inputs
```yaml
inputs:
  base_ref:
    description: 'Base ref for the test'
    required: true
  tags:
    description: 'Tags for the test'
    required: true
  github_token:
    description: 'GitHub token for API access'
    required: true
  TYK_DB_LICENSEKEY:
    description: 'Tyk DB license key'
    required: true
  TYK_MDCB_LICENSE:
    description: 'Tyk MDCB license key'
    required: true
```

#### Current Outputs
```yaml
outputs:
  USER_API_SECRET:
    description: 'User API secret for the test'
    value: ${{ steps.env_up.outputs.USER_API_SECRET }}
```

#### How Dashboard Image is Currently Resolved

The action does **NOT** directly specify dashboard images. Instead, it:

1. **Uses `gromit policy match`** command to determine versions:
   ```bash
   docker run -q --rm -v ~/.docker/config.json:/root/.docker/config.json \
     tykio/gromit policy match ${non_sha_tag} ${match_tag} 2>versions.env
   ```

2. **Creates `versions.env`** file with image tags (written by gromit to stderr, redirected to file)

3. **Hardcodes ECR registry:**
   ```bash
   ECR: "754489498669.dkr.ecr.eu-central-1.amazonaws.com"
   ```

4. **Appends overrides to versions.env:**
   ```bash
   tyk_image="$ECR/tyk-ee"
   tyk_alfa_image=$tyk_image
   tyk_beta_image=$tyk_image
   confs_dir=./pro-ha
   env_file=local.env
   ```

5. **Uses docker-compose** with the generated `versions.env` file:
   ```bash
   docker compose -p auto -f pro-ha.yml -f deps_pro-ha.yml \
     -f ${{ matrix.envfiles.db }}.yml -f ${{ matrix.envfiles.cache }}.yml \
     --env-file versions.env --profile master-datacenter up --quiet-pull -d
   ```

#### Critical Discovery: Dashboard Image Comes from `gromit policy match`

The dashboard image is **NOT explicitly set in the action**. It's determined by:
- The `gromit` tool which reads a policy configuration
- The policy matches gateway tags to dashboard/pump/sink versions
- The result is written to `versions.env` which docker-compose reads

**This means we need to override the dashboard image AFTER `gromit` runs, before docker-compose runs.**

---

### 2. `checkout-tyk-pro` Action

**Location:** `.github/actions/tests/checkout-tyk-pro/action.yaml`

#### What It Does
```yaml
- name: fetch env from tyk-pro
  shell: bash
  env:
    GH_TOKEN: ${{ inputs.org_gh_token }}
  run: |
    gh release download --repo github.com/TykTechnologies/tyk-pro \
      --archive tar.gz -O env.tgz
    mkdir auto && tar --strip-components=1 -C auto -xzvf env.tgz
```

**Purpose:** Downloads the latest release from `tyk-pro` repository (NOT tyk-analytics!), which contains:
- Docker compose files (`pro-ha.yml`, `deps_pro-ha.yml`, etc.)
- Configuration files
- Test environment setup scripts (`dash-bootstrap.sh`)

**Note:** This is downloading infrastructure/environment files, not the dashboard code itself.

---

### 3. `choose-test-branch` Action

**Location:** `.github/actions/tests/choose-test-branch/action.yaml`

#### Inputs
```yaml
inputs:
  test_folder:
    description: 'Folder with tests: api or ui'
    required: true
  branch:
    description: 'Branch with code. If not provided it will be taken from the event'
    required: false
  org_gh_token:
    description: 'GitHub token for API access'
    required: true
```

#### What It Does

1. **Checks out tyk-analytics repository** (sparse checkout of tests folder only):
   ```yaml
   - uses: actions/checkout@v4
     with:
       repository: TykTechnologies/tyk-analytics
       path: tyk-analytics
       sparse-checkout: tests/${{ inputs.test_folder }}
   ```

2. **Intelligently selects branch** based on event type:
   - **For Pull Requests:** Tries PR branch first, falls back to target branch
   - **For Push:** Uses pushed branch name
   - **For Tags:** Uses tag name
   - **Manual override:** Uses `inputs.branch` if provided

3. **Branch Selection Logic:**
   ```bash
   if [[ ${{ github.event_name }} == "pull_request" ]]; then
     PR_BRANCH=${{ github.event.pull_request.head.ref }}
     TARGET_BRANCH=${{ github.event.pull_request.base.ref }}
     if git rev-parse --verify "origin/$PR_BRANCH"; then
       git checkout "$PR_BRANCH"
     elif git rev-parse --verify "origin/$TARGET_BRANCH"; then
       git checkout "$TARGET_BRANCH"
     fi
   fi
   ```

**Key Insight:** This action ONLY checks out test code from tyk-analytics, NOT the dashboard binary/docker image.

---

## Critical Understanding: The Architecture

### Current Flow

```
┌─────────────────────────────────────────────────────────────────┐
│ checkout-tyk-pro                                                │
│ ↓                                                               │
│ Downloads tyk-pro release (docker-compose files, scripts)       │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ env-up                                                          │
│ ↓                                                               │
│ 1. Runs gromit policy match → generates versions.env           │
│ 2. versions.env contains: tyk_dashboard_image, tyk_pump_image  │
│ 3. Overrides tyk_image with ECR/tyk-ee                         │
│ 4. docker-compose reads versions.env                           │
│ 5. Starts all services (gateway, dashboard, pump, etc.)        │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ choose-test-branch                                              │
│ ↓                                                               │
│ Checks out test code from tyk-analytics (Python tests)         │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ api-tests                                                       │
│ ↓                                                               │
│ Runs Python tests against running services                     │
└─────────────────────────────────────────────────────────────────┘
```

### The Problem

**Dashboard image is determined by `gromit policy match`**, which:
- Uses a policy configuration (likely in tyk-pro repo)
- Matches gateway version to compatible dashboard version
- We don't control this directly from workflow inputs

**To override dashboard image, we need to:**
1. Let gromit run normally (to get pump, sink, other versions)
2. Override the dashboard image variable in `versions.env`
3. Pass the modified `versions.env` to docker-compose

---

## Required Modifications

### Option A: Simple Override (Recommended)

Add `dashboard_image` input to `env-up` action and override after gromit runs.

#### Modified `env-up` action:

```yaml
inputs:
  # ... existing inputs ...
  dashboard_image:
    description: 'Override dashboard image (optional, uses gromit policy if not provided)'
    required: false
    default: ''
```

```bash
# After gromit runs and creates versions.env
docker run -q --rm -v ~/.docker/config.json:/root/.docker/config.json \
  tykio/gromit policy match ${non_sha_tag} ${match_tag} 2>versions.env

# NEW: Override dashboard image if provided
if [ -n "${{ inputs.dashboard_image }}" ]; then
  echo "Overriding dashboard image with: ${{ inputs.dashboard_image }}"
  # Append override to versions.env (takes precedence)
  echo "tyk_dashboard_image=${{ inputs.dashboard_image }}" >> versions.env
  # May also need to override related variables:
  echo "tyk_dashboard_master_image=${{ inputs.dashboard_image }}" >> versions.env
  echo "tyk_dashboard_slave_image=${{ inputs.dashboard_image }}" >> versions.env
fi

# Continue with existing logic...
echo '# alfa and beta have to come after the override
tyk_image="$ECR/tyk-ee"
...
```

**Impact:** Minimal, backward compatible, simple to implement

---

### Option B: Full Control (More Complex)

Create a new `resolve-dashboard-image` action in github-actions repo that encapsulates all the logic.

**Location:** `.github/actions/tests/resolve-dashboard-image/action.yaml`

**Benefits:**
- Reusable across repos (tyk, tyk-pump, tyk-sink)
- Centralized logic
- Easier to maintain

**Implementation:** See separate section below

---

## Docker Compose Variables

Based on the code analysis, the docker-compose files likely use these variables:

- `tyk_image` - Gateway image (overridden in action)
- `tyk_dashboard_image` - Dashboard image (set by gromit)
- `tyk_pump_image` - Pump image (set by matrix or gromit)
- `tyk_sink_image` - Sink image (set by matrix or gromit)
- Plus variants: `tyk_dashboard_master_image`, `tyk_dashboard_slave_image`

**We need to verify** the exact variable names by checking the docker-compose files in tyk-pro repo.

---

## Next Steps for Implementation

### Step 1: Verify Docker Compose Variable Names

**Action needed:**
```bash
# Clone or access tyk-pro repo
# Look at pro-ha.yml and find the dashboard service
# Identify the exact variable name used for dashboard image
```

**Possible locations:**
- `${tyk_dashboard_image}`
- `${tyk_dash_image}`
- `${dashboard_image}`

### Step 2: Implement Simple Override in env-up

1. Add `dashboard_image` input
2. Add override logic after gromit runs
3. Test with manual image override

### Step 3: Update tyk release.yml

Use the new input:

```yaml
- name: Set up test environment
  uses: TykTechnologies/github-actions/.github/actions/tests/env-up@main
  with:
    base_ref: ${{ env.BASE_REF }}
    tags: ${{ needs.goreleaser.outputs.ee_tags }}
    dashboard_image: ${{ needs.resolve-dashboard-image.outputs.dashboard_image }}  # NEW
    github_token: ${{ secrets.ORG_GH_TOKEN }}
    TYK_DB_LICENSEKEY: ${{ secrets.DASH_LICENSE }}
    TYK_MDCB_LICENSE: ${{ secrets.MDCB_LICENSE }}
```

---

## Recommended Implementation Plan

### Phase 1.1: Verify Variable Names (NEXT STEP)

**TODO:**
- [ ] Access tyk-pro repository
- [ ] Review `pro-ha.yml` docker-compose file
- [ ] Identify exact dashboard image variable names
- [ ] Check if there are master/slave variants

### Phase 1.2: Modify env-up Action

**TODO:**
- [ ] Add `dashboard_image` input parameter
- [ ] Add conditional override logic after gromit
- [ ] Ensure backward compatibility (empty input = use gromit)
- [ ] Add debug output to show which image is used

### Phase 1.3: Test env-up Changes

**TODO:**
- [ ] Create test workflow in github-actions repo
- [ ] Test with default (no override)
- [ ] Test with custom image override
- [ ] Verify docker-compose uses correct image

---

## Alternative Approach: New Composite Action

If we want better reusability, create:

**`.github/actions/tests/resolve-dashboard-image/action.yaml`**

```yaml
name: 'Resolve Dashboard Image'
description: 'Determines which tyk-analytics image to use based on branch, ECR, or build requirement'
inputs:
  commit_sha:
    description: 'Commit SHA from tyk-gateway'
    required: true
  head_ref:
    description: 'PR head ref/branch name'
    required: false
  base_ref:
    description: 'Base ref/target branch'
    required: true
  ecr_registry:
    description: 'ECR registry URL'
    required: true
  org_gh_token:
    description: 'GitHub token for API access'
    required: true
outputs:
  dashboard_image:
    description: 'Resolved dashboard image to use'
    value: ${{ steps.resolve.outputs.dashboard_image }}
  needs_build:
    description: 'Whether dashboard needs to be built'
    value: ${{ steps.resolve.outputs.needs_build }}
  dashboard_branch:
    description: 'Branch to use for build'
    value: ${{ steps.resolve.outputs.dashboard_branch }}
  strategy:
    description: 'Resolution strategy used (branch/image/build)'
    value: ${{ steps.resolve.outputs.strategy }}

runs:
  using: "composite"
  steps:
    - name: Check if tyk-analytics branch exists
      id: check_branch
      shell: bash
      env:
        GITHUB_TOKEN: ${{ inputs.org_gh_token }}
        HEAD_REF: ${{ inputs.head_ref }}
      run: |
        if [ -z "$HEAD_REF" ]; then
          echo "branch_exists=false" >> $GITHUB_OUTPUT
          exit 0
        fi

        BRANCH=${HEAD_REF##*/}

        if git ls-remote --heads https://github.com/TykTechnologies/tyk-analytics.git refs/heads/$BRANCH | grep -q .; then
          echo "✓ Branch $BRANCH exists in tyk-analytics"
          echo "branch_exists=true" >> $GITHUB_OUTPUT
          echo "branch=$BRANCH" >> $GITHUB_OUTPUT
        else
          echo "✗ Branch $BRANCH not found in tyk-analytics"
          echo "branch_exists=false" >> $GITHUB_OUTPUT
        fi

    - name: Check if ECR image exists with commit SHA
      id: check_ecr
      shell: bash
      env:
        REGISTRY: ${{ inputs.ecr_registry }}
        COMMIT_SHA: ${{ inputs.commit_sha }}
      run: |
        IMAGE_TAG="sha-${COMMIT_SHA}"

        echo "Checking for ECR image: tyk-analytics:${IMAGE_TAG}"

        if aws ecr describe-images \
          --repository-name tyk-analytics \
          --image-ids imageTag=${IMAGE_TAG} \
          --region eu-central-1 2>/dev/null | grep -q imageId; then
          echo "✓ ECR image exists: ${IMAGE_TAG}"
          echo "image_exists=true" >> $GITHUB_OUTPUT
          echo "image_tag=${IMAGE_TAG}" >> $GITHUB_OUTPUT
        else
          echo "✗ ECR image not found: ${IMAGE_TAG}"
          echo "image_exists=false" >> $GITHUB_OUTPUT
        fi

    - name: Resolve dashboard image strategy
      id: resolve
      shell: bash
      env:
        REGISTRY: ${{ inputs.ecr_registry }}
        BRANCH_EXISTS: ${{ steps.check_branch.outputs.branch_exists }}
        IMAGE_EXISTS: ${{ steps.check_ecr.outputs.image_exists }}
        BRANCH: ${{ steps.check_branch.outputs.branch }}
        IMAGE_TAG: ${{ steps.check_ecr.outputs.image_tag }}
        BASE_REF: ${{ inputs.base_ref }}
        COMMIT_SHA: ${{ inputs.commit_sha }}
      run: |
        echo "=== Dashboard Image Resolution ==="
        echo "Branch exists: $BRANCH_EXISTS"
        echo "Image exists: $IMAGE_EXISTS"
        echo "Branch name: $BRANCH"
        echo "Image tag: $IMAGE_TAG"
        echo "Base ref: $BASE_REF"
        echo "=================================="

        if [ "$BRANCH_EXISTS" = "true" ]; then
          # Strategy 1: Use existing branch-based image from gromit
          echo "📋 Strategy: Use gromit policy for branch '$BRANCH'"
          echo "dashboard_image=" >> $GITHUB_OUTPUT  # Empty = use gromit default
          echo "needs_build=false" >> $GITHUB_OUTPUT
          echo "dashboard_branch=$BRANCH" >> $GITHUB_OUTPUT
          echo "strategy=gromit-branch" >> $GITHUB_OUTPUT

        elif [ "$IMAGE_EXISTS" = "true" ]; then
          # Strategy 2: Use existing ECR image with commit SHA
          echo "🐳 Strategy: Use existing ECR image '$IMAGE_TAG'"
          echo "dashboard_image=${REGISTRY}/tyk-analytics:${IMAGE_TAG}" >> $GITHUB_OUTPUT
          echo "needs_build=false" >> $GITHUB_OUTPUT
          echo "dashboard_branch=" >> $GITHUB_OUTPUT
          echo "strategy=ecr-image" >> $GITHUB_OUTPUT

        else
          # Strategy 3: Build required
          echo "🔨 Strategy: Build dashboard from '$BASE_REF' with gateway SHA"
          echo "dashboard_image=${REGISTRY}/tyk-analytics:sha-${COMMIT_SHA}" >> $GITHUB_OUTPUT
          echo "needs_build=true" >> $GITHUB_OUTPUT
          echo "dashboard_branch=$BASE_REF" >> $GITHUB_OUTPUT
          echo "strategy=build-required" >> $GITHUB_OUTPUT
        fi
```

**Benefits:**
- Encapsulates all resolution logic
- Reusable across tyk, tyk-pump, tyk-sink repos
- Clear outputs and strategy reporting
- Easy to test independently

---

## Summary of Findings

### ✅ What We Learned

1. **Dashboard image is resolved by `gromit policy match`** - not directly specified
2. **Override is possible** by modifying `versions.env` after gromit runs
3. **`choose-test-branch` already has smart branch selection** - we can reuse this pattern
4. **`checkout-tyk-pro` downloads docker-compose files** - not dashboard code
5. **Test code is separate from dashboard binary** - they're independently versioned

### 🔧 Modification Required

**Minimal change to `env-up` action:**
- Add `dashboard_image` optional input
- Override `versions.env` if input provided
- Maintain backward compatibility

### ⚠️ Unknowns / Need Verification

1. **Exact variable name** used in docker-compose for dashboard image
2. **Whether there are variants** (master/slave dashboard images)
3. **tyk-analytics build process** - how it works, what it needs
4. **ECR repository** - does `tyk-analytics` repo exist in ECR?
5. **IAM permissions** - can tyk workflow push to tyk-analytics ECR?

---

## Next Action Items

### Immediate (Before Implementation)

- [ ] Access tyk-pro repository and review docker-compose files
- [ ] Identify exact dashboard image variable names
- [ ] Access tyk-analytics repository and review build process
- [ ] Check if tyk-analytics ECR repository exists
- [ ] Verify IAM role permissions for ECR push

### Implementation Phase

- [ ] Modify env-up action with dashboard_image input
- [ ] Test env-up changes in isolation
- [ ] Implement resolve-dashboard-image job in tyk repo
- [ ] Implement build-dashboard-image job in tyk repo
- [ ] Modify api-tests job to use resolved image
- [ ] End-to-end testing

---

**Status:** Phase 1 analysis complete, ready to proceed to verification and implementation phases.
