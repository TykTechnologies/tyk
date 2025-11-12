# Cross-Repo Dashboard Build for API Tests - Implementation Plan

## 📋 Overview

This document outlines the plan to improve the CI workflow for api-tests in `.github/workflows/release.yml` by implementing intelligent dashboard image resolution and conditional building.

## 🎯 Objective

Enable the tyk-gateway CI to run API tests with the correct tyk-analytics (dashboard) version by:

1. Checking if a branch exists on tyk-analytics with the same name as the PR branch
2. If no branch exists, checking if an ECR image exists with the current commit SHA
3. If no image exists, building dashboard from the target branch with updated gateway reference
4. Running API tests with the resolved dashboard image

## 📊 Current State Analysis

### Existing Workflow (release.yml)

**api-tests Job (lines 303-372):**
1. **Line 343**: `checkout-tyk-pro` action checks out tyk-analytics repository
2. **Line 347**: `env-up` action spins up test environment using pre-built dashboard images
3. **Line 357**: `choose-test-branch` action selects test code from tyk-analytics
4. **Line 362**: `api-tests` action runs the actual tests

**Current Limitation:** The workflow assumes a pre-built tyk-analytics image exists. There's no fallback mechanism to build dashboard when needed.

### Branch Selection Logic

```yaml
BASE_REF: ${{startsWith(github.event_name, 'pull_request') && github.base_ref || github.ref_name}}
```

- **For Pull Requests:** Uses `github.base_ref` (target branch, typically `master`)
- **For Pushes/Tags:** Uses `github.ref_name` (branch or tag name)

### ECR Integration

- ECR Registry: `754489498669.dkr.ecr.eu-central-1.amazonaws.com`
- IAM Role: `arn:aws:iam::754489498669:role/ecr_rw_tyk`
- Current image tags: `tyk-ee:sha-<commit>`, `tyk:sha-<commit>`

## 🎯 Proposed Solution

### High-Level Workflow

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Dashboard Image Resolution Job (NEW)                     │
│    - Check if tyk-analytics branch exists                   │
│    - Check if ECR image with commit SHA exists              │
│    - Decide: use existing image OR trigger build            │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ├─ Branch exists? → Use existing workflow
                  │
                  ├─ Image exists? → Use ECR image
                  │
                  └─ Neither? ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. Build Dashboard (CONDITIONAL)                            │
│    - Checkout tyk-analytics on target branch                │
│    - Update gateway reference to PR HEAD SHA                │
│    - Build dashboard binary & docker image                  │
│    - Push to ECR with SHA tag                               │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ↓
┌─────────────────────────────────────────────────────────────┐
│ 3. Run API Tests (EXISTING, with modifications)            │
│    - Use resolved dashboard image                           │
│    - Run tests as normal                                    │
└─────────────────────────────────────────────────────────────┘
```

## 📝 Detailed Implementation Steps

### Step 1: Create Dashboard Image Resolver Job

This new job will run **before** `api-tests` and determine which dashboard image to use.

**New job: `resolve-dashboard-image`**

```yaml
resolve-dashboard-image:
  runs-on: ubuntu-latest
  needs: goreleaser
  permissions:
    id-token: write
    contents: read
  outputs:
    dashboard_image: ${{ steps.resolve.outputs.dashboard_image }}
    needs_build: ${{ steps.resolve.outputs.needs_build }}
    dashboard_branch: ${{ steps.resolve.outputs.dashboard_branch }}
  steps:
    - name: Configure AWS credentials
      uses: aws-actions/configure-aws-credentials@v4
      with:
        role-to-assume: arn:aws:iam::754489498669:role/ecr_rw_tyk
        role-session-name: cipush
        aws-region: eu-central-1

    - name: Login to Amazon ECR
      id: ecr
      uses: aws-actions/amazon-ecr-login@v2
      with:
        mask-password: 'true'

    - name: Check tyk-analytics branch exists
      id: check_branch
      env:
        GITHUB_TOKEN: ${{ secrets.ORG_GH_TOKEN }}
        HEAD_REF: ${{ github.head_ref }}
      run: |
        # Use GitHub API to check if branch exists in tyk-analytics
        BRANCH=${HEAD_REF##*/}
        if git ls-remote --heads https://github.com/TykTechnologies/tyk-analytics.git refs/heads/$BRANCH | grep -q .; then
          echo "branch_exists=true" >> $GITHUB_OUTPUT
          echo "branch=$BRANCH" >> $GITHUB_OUTPUT
        else
          echo "branch_exists=false" >> $GITHUB_OUTPUT
          echo "branch=" >> $GITHUB_OUTPUT
        fi

    - name: Check ECR for commit SHA image
      id: check_ecr
      env:
        REGISTRY: ${{ steps.ecr.outputs.registry }}
      run: |
        # Query ECR for tyk-analytics:sha-${{ github.sha }}
        IMAGE_TAG="sha-${{ github.sha }}"
        if aws ecr describe-images \
          --repository-name tyk-analytics \
          --image-ids imageTag=$IMAGE_TAG \
          --region eu-central-1 2>/dev/null | grep -q imageId; then
          echo "image_exists=true" >> $GITHUB_OUTPUT
          echo "image_tag=$IMAGE_TAG" >> $GITHUB_OUTPUT
        else
          echo "image_exists=false" >> $GITHUB_OUTPUT
          echo "image_tag=" >> $GITHUB_OUTPUT
        fi

    - name: Resolve dashboard image strategy
      id: resolve
      env:
        REGISTRY: ${{ steps.ecr.outputs.registry }}
        BRANCH_EXISTS: ${{ steps.check_branch.outputs.branch_exists }}
        IMAGE_EXISTS: ${{ steps.check_ecr.outputs.image_exists }}
        BRANCH: ${{ steps.check_branch.outputs.branch }}
        IMAGE_TAG: ${{ steps.check_ecr.outputs.image_tag }}
        BASE_REF: ${{ env.BASE_REF }}
      run: |
        if [ "$BRANCH_EXISTS" = "true" ]; then
          # Use existing branch workflow
          echo "dashboard_image=${REGISTRY}/tyk-analytics:${BRANCH}" >> $GITHUB_OUTPUT
          echo "needs_build=false" >> $GITHUB_OUTPUT
          echo "dashboard_branch=${BRANCH}" >> $GITHUB_OUTPUT
          echo "strategy=existing-branch" >> $GITHUB_OUTPUT
        elif [ "$IMAGE_EXISTS" = "true" ]; then
          # Use existing ECR image
          echo "dashboard_image=${REGISTRY}/tyk-analytics:${IMAGE_TAG}" >> $GITHUB_OUTPUT
          echo "needs_build=false" >> $GITHUB_OUTPUT
          echo "dashboard_branch=" >> $GITHUB_OUTPUT
          echo "strategy=existing-image" >> $GITHUB_OUTPUT
        else
          # Need to build
          echo "dashboard_image=${REGISTRY}/tyk-analytics:sha-${{ github.sha }}" >> $GITHUB_OUTPUT
          echo "needs_build=true" >> $GITHUB_OUTPUT
          echo "dashboard_branch=${BASE_REF}" >> $GITHUB_OUTPUT
          echo "strategy=build-required" >> $GITHUB_OUTPUT
        fi
```

**Outputs:**
- `dashboard_image`: Full image path/tag to use
- `needs_build`: Boolean if we need to build dashboard
- `dashboard_branch`: Branch name to checkout for build

### Step 2: Conditional Dashboard Build Job

This job only runs if `needs_build == true`.

**New job: `build-dashboard-image`**

```yaml
build-dashboard-image:
  runs-on: ubuntu-latest-m
  needs: resolve-dashboard-image
  if: needs.resolve-dashboard-image.outputs.needs_build == 'true'
  permissions:
    id-token: write
    contents: read
  outputs:
    dashboard_image: ${{ steps.build.outputs.image }}
  steps:
    - name: Checkout tyk-analytics
      uses: actions/checkout@v4
      with:
        repository: TykTechnologies/tyk-analytics
        ref: ${{ needs.resolve-dashboard-image.outputs.dashboard_branch }}
        token: ${{ secrets.ORG_GH_TOKEN }}
        fetch-depth: 1

    - name: Update gateway reference
      run: |
        # Update go.mod or dependency file to point to PR HEAD SHA
        # This depends on how tyk-analytics references tyk-gateway
        # Example: go get github.com/TykTechnologies/tyk@${{ github.sha }}
        go get github.com/TykTechnologies/tyk@${{ github.sha }}
        go mod tidy

    - name: Configure AWS credentials
      uses: aws-actions/configure-aws-credentials@v4
      with:
        role-to-assume: arn:aws:iam::754489498669:role/ecr_rw_tyk
        role-session-name: cipush
        aws-region: eu-central-1

    - name: Login to Amazon ECR
      id: ecr
      uses: aws-actions/amazon-ecr-login@v2
      with:
        mask-password: 'true'

    - uses: docker/setup-qemu-action@v3
    - uses: docker/setup-buildx-action@v3

    - name: Build and push dashboard image
      id: build
      uses: docker/build-push-action@v6
      with:
        context: .
        platforms: linux/amd64,linux/arm64
        push: true
        cache-from: type=gha
        cache-to: type=gha,mode=max
        tags: ${{ steps.ecr.outputs.registry }}/tyk-analytics:sha-${{ github.sha }}
        labels: |
          org.opencontainers.image.revision=${{ github.sha }}
          org.opencontainers.image.source=https://github.com/TykTechnologies/tyk-analytics

    - name: Output image
      run: |
        echo "image=${{ steps.ecr.outputs.registry }}/tyk-analytics:sha-${{ github.sha }}" >> $GITHUB_OUTPUT
```

### Step 3: Modify Existing api-tests Job

Update the existing job to use the resolved dashboard image:

```yaml
api-tests:
  needs:
    - test-controller-api
    - goreleaser
    - resolve-dashboard-image
  runs-on: ubuntu-latest-m-2
  env:
    XUNIT_REPORT_PATH: ${{ github.workspace}}/test-results.xml
  permissions:
    id-token: write
    contents: read
  strategy:
    fail-fast: false
    matrix:
      envfiles: ${{ fromJson(needs.test-controller-api.outputs.envfiles) }}
      pump: ${{ fromJson(needs.test-controller-api.outputs.pump) }}
      sink: ${{ fromJson(needs.test-controller-api.outputs.sink) }}
      exclude:
        - pump: tykio/tyk-pump-docker-pub:v1.8
          sink: $ECR/tyk-sink:master
        - pump: $ECR/tyk-pump:master
          sink: tykio/tyk-mdcb-docker:v2.4
  steps:
    # ... existing AWS configuration steps ...

    - name: Fetch environment from tyk-pro
      uses: TykTechnologies/github-actions/.github/actions/tests/checkout-tyk-pro@main
      with:
        org_gh_token: ${{ github.token }}

    - name: Set up test environment
      uses: TykTechnologies/github-actions/.github/actions/tests/env-up@main
      timeout-minutes: 5
      id: env_up
      with:
        base_ref: ${{ env.BASE_REF }}
        tags: ${{ needs.goreleaser.outputs.ee_tags || needs.goreleaser.outputs.std_tags || format('{0}/tyk-ee:master', steps.ecr.outputs.registry) }}
        dashboard_image: ${{ needs.resolve-dashboard-image.outputs.dashboard_image }}  # NEW
        github_token: ${{ secrets.ORG_GH_TOKEN }}
        TYK_DB_LICENSEKEY: ${{ secrets.DASH_LICENSE }}
        TYK_MDCB_LICENSE: ${{ secrets.MDCB_LICENSE }}

    # ... rest of existing steps ...
```

**Note:** The job dependency will automatically wait for `build-dashboard-image` if it runs, since `resolve-dashboard-image` is a dependency and the build job depends on it.

## 🔧 Required Changes in Other Repositories/Actions

### Changes Needed in `TykTechnologies/github-actions`

Located at: `~/works/github-actions`

#### 1. **`env-up` Action** (REQUIRED - HIGH PRIORITY)

**File:** `.github/actions/tests/env-up/action.yml`

**Current behavior:** Probably uses hardcoded or convention-based dashboard image tags

**Required change:**

```yaml
inputs:
  dashboard_image:
    description: 'Override dashboard image to use for tyk-analytics'
    required: false
    default: ''
  # ... existing inputs ...
```

**Implementation in action:**
- Check if `dashboard_image` input is provided
- If yes, use it instead of default image resolution
- If no, fall back to existing behavior (backward compatible)

**Impact:** HIGH - This is a blocker for the implementation

#### 2. **`checkout-tyk-pro` Action** (OPTIONAL - Enhancement)

**File:** `.github/actions/tests/checkout-tyk-pro/action.yml`

**Current behavior:** Checks out tyk-analytics on a matching branch

**Potential enhancement:**

```yaml
inputs:
  branch:
    description: 'Specific branch to checkout (overrides auto-detection)'
    required: false
  skip_if_branch_missing:
    description: 'Skip checkout if branch does not exist'
    required: false
    default: 'false'
```

**Impact:** LOW - Optional, existing logic may already handle this

#### 3. **`choose-test-branch` Action** (NO CHANGE)

**File:** `.github/actions/tests/choose-test-branch/action.yml`

**Current behavior:** Selects test code branch based on tyk branch

**Required change:** None - this already handles branch resolution

**Impact:** None - can reuse existing logic

### New Composite Action (OPTIONAL - Recommended)

Create a new action to encapsulate the resolution logic:

**File:** `.github/actions/tests/resolve-dashboard-image/action.yml`

This action would handle:
- Checking branch existence in tyk-analytics
- Querying ECR for images
- Deciding build strategy
- Returning appropriate outputs

**Benefits:**
- Reusable across multiple repos (tyk, tyk-pump, etc.)
- Centralized logic
- Easier to test and maintain
- Single source of truth

**Structure:**

```yaml
name: Resolve Dashboard Image
description: Determines which tyk-analytics image to use for testing
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
    description: 'Image to use'
  needs_build:
    description: 'Whether build is needed'
  dashboard_branch:
    description: 'Branch to checkout for build'
  strategy:
    description: 'Resolution strategy used'
```

### Changes in `TykTechnologies/tyk-analytics`

#### 1. Verify Build Automation

**Questions to answer:**
- Does tyk-analytics have a Dockerfile? ✓ (Need to verify location)
- Does it have automated builds (goreleaser, CI workflow)?
- Can it build from arbitrary gateway SHAs?
- How does it reference tyk-gateway (go.mod, vendor, other)?

**Action items:**
- [ ] Review tyk-analytics repository structure
- [ ] Identify build process
- [ ] Verify Dockerfile exists and works
- [ ] Test updating gateway reference

#### 2. ECR Repository Setup

**Questions to answer:**
- Does `tyk-analytics` ECR repository exist?
- Does the IAM role have push permissions?
- What's the lifecycle policy?

**Action items:**
- [ ] Verify ECR repository: `tyk-analytics`
- [ ] Verify IAM permissions for `ecr_rw_tyk` role
- [ ] Set up ECR lifecycle policy to clean old images

## 🏗️ Implementation Order

### Phase 1: Prepare github-actions Repository (DO FIRST)

**Priority: HIGH - These are blockers**

1. **Review and modify `env-up` action**
   - [ ] Read current implementation in `~/works/github-actions/.github/actions/tests/env-up`
   - [ ] Add `dashboard_image` input parameter
   - [ ] Implement logic to use custom image if provided
   - [ ] Test with manual image override
   - [ ] Ensure backward compatibility (existing workflows unaffected)

2. **(Optional) Create new `resolve-dashboard-image` composite action**
   - [ ] Create action directory structure
   - [ ] Implement branch checking logic (GitHub API)
   - [ ] Implement ECR image checking logic (AWS CLI)
   - [ ] Add comprehensive outputs
   - [ ] Write action documentation

3. **Test in isolation**
   - [ ] Create test workflow in github-actions repo
   - [ ] Verify all code paths work correctly
   - [ ] Test with real tyk-analytics repository

### Phase 2: Investigate tyk-analytics Repository

**Priority: MEDIUM - Need information to proceed**

1. **Analyze build process**
   - [ ] Clone/access tyk-analytics repository
   - [ ] Locate Dockerfile and build scripts
   - [ ] Understand how gateway dependency is managed
   - [ ] Document build process

2. **Test local build**
   - [ ] Try building dashboard locally
   - [ ] Update gateway reference to a specific SHA
   - [ ] Verify build succeeds
   - [ ] Note any special requirements or secrets needed

3. **Verify ECR access**
   - [ ] Check if `tyk-analytics` ECR repo exists
   - [ ] Test IAM permissions for push
   - [ ] Configure lifecycle policies if needed

### Phase 3: Update tyk Repository (FINAL STEP)

**Priority: HIGH - Main implementation**

1. **Add `resolve-dashboard-image` job** to release.yml
   - [ ] Implement job with branch checking
   - [ ] Implement ECR image checking
   - [ ] Set up proper outputs

2. **Add conditional `build-dashboard-image` job**
   - [ ] Checkout tyk-analytics logic
   - [ ] Gateway reference update logic
   - [ ] Docker build and push logic
   - [ ] Only runs when needed

3. **Modify `api-tests` job**
   - [ ] Add dependency on `resolve-dashboard-image`
   - [ ] Pass resolved image to `env-up`
   - [ ] Test backward compatibility

4. **End-to-end testing**
   - [ ] Test with PR that has matching tyk-analytics branch
   - [ ] Test with PR that has no branch but ECR image exists
   - [ ] Test with PR that needs full build
   - [ ] Verify test results are valid

## 🚨 Key Considerations & Risks

### 1. ECR Permissions

**Risk:** tyk workflow may not have permission to push to tyk-analytics ECR repository

**Questions:**
- Does IAM role `ecr_rw_tyk` have access to tyk-analytics repo?
- Are there separate ECR repositories or shared?

**Mitigation:**
- Verify permissions before implementation
- Update IAM policies if needed
- Document required permissions

### 2. Build Time Impact

**Risk:** Building dashboard from scratch adds 5-15 minutes to CI time

**Impact:**
- Only affects PRs without matching branches
- Most PRs will have matching branches (standard workflow)
- Trade-off: completeness vs. speed

**Mitigation:**
- Aggressive Docker layer caching (`cache-from: type=gha`)
- Build only when absolutely necessary
- Consider parallel execution where possible
- Use faster runners (`ubuntu-latest-m`)

### 3. Dependency Management

**Critical Question:** How does tyk-analytics reference tyk-gateway?

**Possible scenarios:**
- **Go modules (go.mod):** `go get github.com/TykTechnologies/tyk@<SHA>`
- **Git submodules:** Update submodule reference
- **Vendor directory:** May need special handling
- **Other:** Custom dependency management

**Action needed:**
- [ ] Investigate tyk-analytics dependency management
- [ ] Test updating gateway reference
- [ ] Document the correct approach

### 4. Image Tagging Strategy

**Current tags in release.yml:**
- `sha-<commit>` for commit-based images
- `<branch>` for branch-based images
- Semver patterns for releases

**For dashboard builds:**
- Use: `tyk-analytics:sha-<tyk-gateway-commit-sha>`
- Consistent with existing convention
- Easy to trace back to gateway commit

**Additional metadata:**
- Add labels with source info
- Tag with PR number if available
- Include build timestamp

### 5. Cleanup Strategy

**Risk:** Building images for every PR creates many ECR images

**ECR storage costs:**
- Each image ~500MB-2GB
- 50 PRs/month = 25-100GB storage
- Auto-cleanup essential

**Mitigation:**
- Set ECR lifecycle policy: delete untagged after 7 days
- Delete SHA-tagged images after 30 days
- Keep branch-tagged images longer
- Consider using digest references instead of tags

### 6. Parallel Execution

**Question:** Can `build-dashboard-image` run in parallel with `test-controller-distros`?

**Current dependencies:**
```
goreleaser
    ├─> test-controller-api ──> api-tests
    ├─> test-controller-distros ──> upgrade-deb, upgrade-rpm
    └─> release-tests
```

**New dependencies:**
```
goreleaser
    ├─> resolve-dashboard-image ──> build-dashboard-image (conditional) ──> api-tests
    ├─> test-controller-api ──> api-tests
    ├─> test-controller-distros ──> upgrade-deb, upgrade-rpm
    └─> release-tests
```

**Optimization:** Resolution and build can run in parallel with distro tests, saving time.

### 7. Failure Handling

**Scenarios:**
- Branch check fails (network/API issue)
- ECR query fails
- Dashboard build fails
- Image push fails

**Strategy:**
- Fail fast on critical errors
- Retry transient failures (network)
- Clear error messages
- Fallback to master branch build if possible

## 📊 Testing Strategy

### Unit Testing (Action Level)

**For `resolve-dashboard-image` action:**
- [ ] Test with existing branch
- [ ] Test with existing ECR image
- [ ] Test with neither (build required)
- [ ] Test with API failures
- [ ] Test with invalid inputs

### Integration Testing (Workflow Level)

**Test cases:**
1. **PR with matching tyk-analytics branch**
   - Expected: Uses existing branch, no build

2. **PR without branch, but ECR image exists**
   - Expected: Uses ECR image, no build

3. **PR without branch or image**
   - Expected: Builds dashboard, uses new image

4. **Push to master**
   - Expected: Uses master branch of dashboard

5. **Release tag**
   - Expected: Uses release workflow (unchanged)

### End-to-End Testing

**Full workflow validation:**
- [ ] Create test PR in tyk repo
- [ ] Verify image resolution works
- [ ] Verify build triggers when needed
- [ ] Verify tests run successfully
- [ ] Verify test results are accurate
- [ ] Check CI duration impact

## 🔄 Alternative Approaches

### Option A: Repository Dispatch to tyk-analytics (More Complex)

Instead of building in tyk repo, orchestrate via events:

**Flow:**
1. tyk workflow sends repository_dispatch to tyk-analytics
2. tyk-analytics builds its own image with updated gateway ref
3. tyk-analytics reports back via commit status API
4. tyk workflow polls/waits for completion
5. tyk workflow uses the built image

**Pros:**
- Separation of concerns
- Each repo manages its own builds
- Cleaner architecture
- Reusable for other repos (tyk-pump, etc.)

**Cons:**
- More complex orchestration
- Harder to debug
- Cross-repo dependencies
- Polling or webhook complexity
- Longer overall time (sequential)

### Option B: Manual Workflow Dispatch Input (Simpler)

Add manual control via workflow inputs:

```yaml
workflow_dispatch:
  inputs:
    use_dashboard_branch:
      description: 'Dashboard branch to use'
      required: false
    force_dashboard_build:
      description: 'Force dashboard rebuild'
      type: boolean
      default: false
```

**Pros:**
- Simple to implement
- Manual control when needed
- No cross-repo automation complexity
- Easy to debug

**Cons:**
- Requires manual intervention
- Not automated
- Easy to forget
- Doesn't solve the core problem

### Option C: Always Build Dashboard (Simplest but Slowest)

Remove intelligence, always build dashboard from target branch:

**Pros:**
- Simplest implementation
- Always tests against latest dashboard code
- No branch checking complexity
- Predictable behavior

**Cons:**
- Significantly slower CI (every PR +10 minutes)
- Wastes resources
- Unnecessary builds for most PRs
- Higher costs

## 📈 Success Metrics

**How to measure success:**

1. **Functionality:** All test scenarios pass
2. **Performance:** Minimal impact on CI time (<5% increase average)
3. **Reliability:** <1% failure rate due to new code
4. **Coverage:** 100% of PRs can run tests
5. **Maintainability:** Clear, documented, testable code

## 📝 Documentation Requirements

**Need to document:**

1. **For developers:** How the new workflow works
2. **For CI/CD:** Troubleshooting guide
3. **For github-actions:** Action usage and inputs
4. **For tyk-analytics:** Build requirements
5. **For operations:** ECR cleanup policies

## ✅ Next Steps

**Before implementing, we need to:**

1. **Verify `env-up` action capabilities**
   - [ ] Read the action code in `~/works/github-actions`
   - [ ] Understand current image resolution
   - [ ] Confirm modification approach

2. **Check tyk-analytics build process**
   - [ ] Access tyk-analytics repository
   - [ ] Document build process
   - [ ] Test dependency update

3. **Verify ECR access and permissions**
   - [ ] Check IAM role permissions
   - [ ] Verify ECR repo exists
   - [ ] Test push access

4. **Choose implementation approach**
   - [ ] Full automated build (recommended)
   - [ ] Repository dispatch
   - [ ] Manual trigger
   - [ ] Hybrid approach

## 🎬 Ready to Start

Once the above prerequisites are checked, we can proceed with implementation in phases:

**Phase 1:** Modify github-actions (env-up action)
**Phase 2:** Investigate tyk-analytics build
**Phase 3:** Implement in tyk repository

---

**Document Version:** 1.0
**Date:** 2025-11-05
**Author:** Claude Code
**Status:** Planning - Ready for Review
