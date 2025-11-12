# Cross-Repo Dashboard Build - Complete Implementation Summary

## Date: 2025-11-05
## Status: ✅ Analysis Complete - Ready for Implementation

---

## 📊 Analysis Complete - Key Findings

### 1. Docker Compose Variable Name: ✅ CONFIRMED

**File:** `tyk-pro/pro-ha.yml` line 24

```yaml
tyk-analytics:
  container_name: tyk-analytics
  image: ${tyk_analytics_image}    # ← This is the variable we need to override
```

**Variable name:** `tyk_analytics_image`

### 2. tyk-analytics Build Process: ✅ CONFIRMED

**Location:** `tyk-analytics/.github/workflows/release.yml`

**Build method:**
- Uses goreleaser (similar to tyk gateway)
- Builds with `tykio/golang-cross:1.24-bullseye`
- Pushes to ECR: `754489498669.dkr.ecr.eu-central-1.amazonaws.com/tyk-analytics`
- Uses IAM role: `arn:aws:iam::754489498669:role/ecr_rw_tyk` (same as gateway)

**Key insight:** tyk-analytics already has complete build automation. We can replicate this process.

### 3. Gateway Dependency Management: ✅ CONFIRMED

**File:** `tyk-analytics/go.mod` line 31

```go
github.com/TykTechnologies/tyk v1.9.2-0.20251101120803-607ce27893db
```

**To update gateway reference:**
```bash
go get github.com/TykTechnologies/tyk@<commit-sha>
go mod tidy
```

### 4. ECR Setup: ✅ VERIFIED

**Registry:** `754489498669.dkr.ecr.eu-central-1.amazonaws.com`
**Repository:** `tyk-analytics` (confirmed from release.yml line 142)
**IAM Role:** Same role used by both repos
**Tag format:** `sha-<commit>` for commit-based images

---

## 🎯 Implementation Strategy

Based on the analysis, here's the **recommended implementation approach**:

### Approach: Direct Build in tyk Workflow (Recommended)

**Why this approach:**
1. ✅ Simpler - all logic in one workflow
2. ✅ Faster - no cross-repo coordination delays
3. ✅ Easier to debug - single workflow to troubleshoot
4. ✅ Same IAM role - no permission issues
5. ✅ Proven pattern - tyk-analytics already builds this way

**Trade-offs:**
- ❌ tyk workflow needs to know about tyk-analytics build
- ✅ But: build process is simple and well-documented

---

## 📋 Complete Implementation Plan

### Phase 1: Modify github-actions Repository

#### File: `.github/actions/tests/env-up/action.yaml`

**Add new input:**

```yaml
inputs:
  # ... existing inputs ...
  dashboard_image:
    description: 'Override dashboard image (optional). If not provided, uses gromit policy matching.'
    required: false
    default: ''
```

**Modify the run step (after line 77):**

```bash
# Existing gromit call
docker run -q --rm -v ~/.docker/config.json:/root/.docker/config.json \
  tykio/gromit policy match ${non_sha_tag} ${match_tag} 2>versions.env

# NEW: Override dashboard image if provided
if [ -n "${{ inputs.dashboard_image }}" ]; then
  echo "🔧 Overriding dashboard image with: ${{ inputs.dashboard_image }}"
  echo "tyk_analytics_image=${{ inputs.dashboard_image }}" >> versions.env
fi

# Existing append logic continues...
echo '# alfa and beta have to come after the override
tyk_image="$ECR/tyk-ee"
...
```

**Testing checklist:**
- [ ] Test with no override (default behavior)
- [ ] Test with custom image override
- [ ] Verify backward compatibility

---

### Phase 2: Add Jobs to tyk Repository

#### Job 1: `resolve-dashboard-image` (NEW)

**Location:** `.github/workflows/release.yml` (add after `test-controller-api`)

```yaml
resolve-dashboard-image:
  if: github.event.pull_request.draft == false
  needs: goreleaser
  runs-on: ubuntu-latest
  permissions:
    id-token: write
    contents: read
  outputs:
    dashboard_image: ${{ steps.resolve.outputs.dashboard_image }}
    needs_build: ${{ steps.resolve.outputs.needs_build }}
    dashboard_branch: ${{ steps.resolve.outputs.dashboard_branch }}
    strategy: ${{ steps.resolve.outputs.strategy }}
  steps:
    - name: Configure AWS credentials
      uses: aws-actions/configure-aws-credentials@v4
      with:
        role-to-assume: arn:aws:iam::754489498669:role/ecr_rw_tyk
        role-session-name: cipush
        aws-region: eu-central-1
        mask-aws-account-id: false

    - name: Login to Amazon ECR
      id: ecr
      uses: aws-actions/amazon-ecr-login@v2
      with:
        mask-password: 'true'

    - name: Check if tyk-analytics branch exists
      id: check_branch
      shell: bash
      env:
        GITHUB_TOKEN: ${{ secrets.ORG_GH_TOKEN }}
        HEAD_REF: ${{ github.head_ref }}
      run: |
        if [ -z "$HEAD_REF" ]; then
          echo "Not a pull request, skipping branch check"
          echo "branch_exists=false" >> $GITHUB_OUTPUT
          exit 0
        fi

        BRANCH=${HEAD_REF##*/}
        echo "Checking for branch: $BRANCH in tyk-analytics"

        if git ls-remote --heads https://$GITHUB_TOKEN@github.com/TykTechnologies/tyk-analytics.git refs/heads/$BRANCH | grep -q .; then
          echo "✓ Branch '$BRANCH' exists in tyk-analytics"
          echo "branch_exists=true" >> $GITHUB_OUTPUT
          echo "branch=$BRANCH" >> $GITHUB_OUTPUT
        else
          echo "✗ Branch '$BRANCH' not found in tyk-analytics"
          echo "branch_exists=false" >> $GITHUB_OUTPUT
        fi

    - name: Check if ECR image exists with commit SHA
      id: check_ecr
      shell: bash
      env:
        REGISTRY: ${{ steps.ecr.outputs.registry }}
        COMMIT_SHA: ${{ github.sha }}
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
        REGISTRY: ${{ steps.ecr.outputs.registry }}
        BRANCH_EXISTS: ${{ steps.check_branch.outputs.branch_exists }}
        IMAGE_EXISTS: ${{ steps.check_ecr.outputs.image_exists }}
        BRANCH: ${{ steps.check_branch.outputs.branch }}
        IMAGE_TAG: ${{ steps.check_ecr.outputs.image_tag }}
        BASE_REF: ${{ env.BASE_REF }}
        COMMIT_SHA: ${{ github.sha }}
      run: |
        echo "=================================="
        echo "📊 Dashboard Image Resolution"
        echo "=================================="
        echo "Branch exists: $BRANCH_EXISTS"
        echo "Image exists: $IMAGE_EXISTS"
        echo "Branch name: $BRANCH"
        echo "Image tag: $IMAGE_TAG"
        echo "Base ref: $BASE_REF"
        echo "Commit SHA: $COMMIT_SHA"
        echo "=================================="

        if [ "$BRANCH_EXISTS" = "true" ]; then
          # Strategy 1: Use gromit policy (matching branch exists)
          echo "📋 Strategy: Let gromit match branch '$BRANCH'"
          echo "    → No override needed, gromit will handle it"
          echo "dashboard_image=" >> $GITHUB_OUTPUT  # Empty = use gromit
          echo "needs_build=false" >> $GITHUB_OUTPUT
          echo "dashboard_branch=$BRANCH" >> $GITHUB_OUTPUT
          echo "strategy=gromit-branch" >> $GITHUB_OUTPUT

        elif [ "$IMAGE_EXISTS" = "true" ]; then
          # Strategy 2: Use existing ECR image
          echo "🐳 Strategy: Use existing ECR image"
          echo "    → Image: ${REGISTRY}/tyk-analytics:${IMAGE_TAG}"
          echo "dashboard_image=${REGISTRY}/tyk-analytics:${IMAGE_TAG}" >> $GITHUB_OUTPUT
          echo "needs_build=false" >> $GITHUB_OUTPUT
          echo "dashboard_branch=" >> $GITHUB_OUTPUT
          echo "strategy=ecr-image" >> $GITHUB_OUTPUT

        else
          # Strategy 3: Build required
          echo "🔨 Strategy: Build dashboard from '$BASE_REF' branch"
          echo "    → Will update gateway ref to $COMMIT_SHA"
          echo "    → Will push to: ${REGISTRY}/tyk-analytics:sha-${COMMIT_SHA}"
          echo "dashboard_image=${REGISTRY}/tyk-analytics:sha-${COMMIT_SHA}" >> $GITHUB_OUTPUT
          echo "needs_build=true" >> $GITHUB_OUTPUT
          echo "dashboard_branch=$BASE_REF" >> $GITHUB_OUTPUT
          echo "strategy=build-required" >> $GITHUB_OUTPUT
        fi

        echo "=================================="
        echo "✅ Resolution complete"
        echo "=================================="
```

---

#### Job 2: `build-dashboard-image` (NEW - CONDITIONAL)

**Location:** `.github/workflows/release.yml` (add after `resolve-dashboard-image`)

```yaml
build-dashboard-image:
  if: needs.resolve-dashboard-image.outputs.needs_build == 'true'
  needs: resolve-dashboard-image
  runs-on: ubuntu-latest-m
  permissions:
    id-token: write
    contents: read
  outputs:
    dashboard_image: ${{ steps.output.outputs.image }}
  steps:
    - name: Checkout tyk-analytics
      uses: actions/checkout@v4
      with:
        repository: TykTechnologies/tyk-analytics
        ref: ${{ needs.resolve-dashboard-image.outputs.dashboard_branch }}
        token: ${{ secrets.ORG_GH_TOKEN }}
        fetch-depth: 1
        submodules: true

    - name: Update gateway reference to PR commit
      shell: bash
      env:
        GATEWAY_SHA: ${{ github.sha }}
      run: |
        echo "📦 Updating tyk-gateway dependency to: $GATEWAY_SHA"

        # Configure git for go get
        git config --global url."https://${{ secrets.ORG_GH_TOKEN }}@github.com".insteadOf "https://github.com"

        # Update dependency
        go get github.com/TykTechnologies/tyk@$GATEWAY_SHA
        go mod tidy

        echo "✅ Updated go.mod:"
        grep "github.com/TykTechnologies/tyk" go.mod

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

    - uses: actions/cache@v4
      with:
        path: |
          ~/.cache/go-build
          ~/go/pkg/mod
        key: ${{ runner.os }}-go-dashboard-${{ hashFiles('**/go.sum') }}
        restore-keys: |
          ${{ runner.os }}-go-dashboard-

    - name: Build dashboard binary and docker image
      shell: bash
      env:
        ECR_REGISTRY: ${{ steps.ecr.outputs.registry }}
        IMAGE_TAG: sha-${{ github.sha }}
        GOPRIVATE: github.com/TykTechnologies
      run: |
        echo "🔨 Building tyk-analytics with goreleaser"
        echo "   Image: ${ECR_REGISTRY}/tyk-analytics:${IMAGE_TAG}"

        # Build using goreleaser (similar to tyk-analytics release workflow)
        cat > /tmp/build-dashboard.sh <<'EOF'
#!/bin/sh
set -eax
git config --global url."https://${{ secrets.ORG_GH_TOKEN }}@github.com".insteadOf "https://github.com"
git config --global --add safe.directory /go/src/github.com/TykTechnologies/tyk-analytics

# Build binaries only (skip packaging)
goreleaser build --clean -f ci/goreleaser/goreleaser.yml --snapshot --single-target
EOF

        chmod +x /tmp/build-dashboard.sh

        # Build in golang-cross container
        docker run --rm --privileged \
          -e GOPRIVATE=github.com/TykTechnologies \
          -e CGO_ENABLED=1 \
          -v ${{ github.workspace }}:/go/src/github.com/TykTechnologies/tyk-analytics \
          -v ~/.cache/go-build:/cache/go-build \
          -v ~/go/pkg/mod:/go/pkg/mod \
          -e GOCACHE=/cache/go-build \
          -e GOMODCACHE=/go/pkg/mod \
          -v /tmp/build-dashboard.sh:/tmp/build-dashboard.sh \
          -w /go/src/github.com/TykTechnologies/tyk-analytics \
          tykio/golang-cross:1.24-bullseye /tmp/build-dashboard.sh

        echo "✅ Binary built successfully"

        # Build and push docker image
        echo "🐳 Building and pushing Docker image"

    - name: Build and push dashboard Docker image
      uses: docker/build-push-action@v6
      with:
        context: .
        file: ./Dockerfile
        platforms: linux/amd64,linux/arm64
        push: true
        cache-from: type=gha
        cache-to: type=gha,mode=max
        tags: ${{ steps.ecr.outputs.registry }}/tyk-analytics:sha-${{ github.sha }}
        labels: |
          org.opencontainers.image.title=Tyk Dashboard (Custom Build)
          org.opencontainers.image.description=Built from ${{ needs.resolve-dashboard-image.outputs.dashboard_branch }} with gateway ${{ github.sha }}
          org.opencontainers.image.revision=${{ github.sha }}
          org.opencontainers.image.source=https://github.com/TykTechnologies/tyk-analytics
          tyk.gateway.commit=${{ github.sha }}
          tyk.dashboard.branch=${{ needs.resolve-dashboard-image.outputs.dashboard_branch }}

    - name: Output image reference
      id: output
      shell: bash
      run: |
        IMAGE="${{ steps.ecr.outputs.registry }}/tyk-analytics:sha-${{ github.sha }}"
        echo "image=$IMAGE" >> $GITHUB_OUTPUT
        echo "✅ Dashboard image built and pushed: $IMAGE"
```

---

#### Job 3: Modify `api-tests` (EXISTING)

**Location:** `.github/workflows/release.yml` (modify existing job)

**Changes needed:**

1. **Add dependency** on `resolve-dashboard-image`:
```yaml
api-tests:
  needs:
    - test-controller-api
    - goreleaser
    - resolve-dashboard-image  # NEW
  runs-on: ubuntu-latest-m-2
```

2. **Pass dashboard image to env-up:**
```yaml
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
```

**Note:** If dashboard_image is empty (gromit-branch strategy), env-up will use default gromit policy. The job will automatically wait for `build-dashboard-image` if it runs because of the dependency chain.

---

## 🔍 How It Works

### Scenario 1: PR with Matching tyk-analytics Branch ✅

```
PR: feat/new-feature
└─> Check tyk-analytics branch: feat/new-feature ✓ EXISTS
    └─> Strategy: gromit-branch
        └─> Pass empty dashboard_image to env-up
            └─> env-up uses gromit policy match
                └─> gromit finds matching branch image
                    └─> Tests run with matching branch ✅
```

**Result:** No build needed, fast CI ⚡

### Scenario 2: ECR Image Exists (Dashboard Already Built) ✅

```
PR: feat/other-feature
└─> Check tyk-analytics branch: feat/other-feature ✗ NOT FOUND
    └─> Check ECR: tyk-analytics:sha-abc123 ✓ EXISTS
        └─> Strategy: ecr-image
            └─> Pass ECR image to env-up
                └─> env-up overrides versions.env
                    └─> Tests run with ECR image ✅
```

**Result:** No build needed, fast CI ⚡

### Scenario 3: Build Required (New Dashboard Needed) 🔨

```
PR: feat/gateway-only-change
└─> Check tyk-analytics branch: feat/gateway-only-change ✗ NOT FOUND
    └─> Check ECR: tyk-analytics:sha-xyz789 ✗ NOT FOUND
        └─> Strategy: build-required
            ├─> build-dashboard-image job RUNS
            │   ├─> Checkout tyk-analytics on master
            │   ├─> Update gateway ref to PR commit SHA
            │   ├─> Build dashboard binary
            │   ├─> Build and push Docker image
            │   └─> Push to ECR: tyk-analytics:sha-xyz789
            └─> api-tests job WAITS for build
                └─> Pass built image to env-up
                    └─> env-up overrides versions.env
                        └─> Tests run with new image ✅
```

**Result:** Build takes ~10 minutes, but ensures compatibility 🎯

---

## ⏱️ Performance Impact

### Current State
- PR without matching branch: ❌ **FAILS** (no dashboard to test with)

### After Implementation
- **Scenario 1** (matching branch): ~5-10 minutes (no change)
- **Scenario 2** (ECR image exists): ~5-10 minutes (+1 min for ECR check)
- **Scenario 3** (build required): ~15-20 minutes (+10-15 min for build)

**Average impact:** Most PRs will hit Scenario 1 or 2, minimal slowdown.

---

## 🧪 Testing Plan

### Unit Tests (Per Component)

**env-up action:**
- [ ] Test with no dashboard_image input (default behavior)
- [ ] Test with custom dashboard_image input
- [ ] Verify versions.env is correctly overridden
- [ ] Verify backward compatibility with existing workflows

**resolve-dashboard-image job:**
- [ ] Test with existing branch (PR has matching dashboard branch)
- [ ] Test with non-existent branch (PR has no matching dashboard branch)
- [ ] Test with existing ECR image
- [ ] Test with non-existent ECR image
- [ ] Test with push event (not PR)
- [ ] Verify outputs are set correctly for each scenario

**build-dashboard-image job:**
- [ ] Test gateway dependency update (`go get`)
- [ ] Test binary build (goreleaser)
- [ ] Test Docker image build
- [ ] Test ECR push
- [ ] Verify image labels are correct

### Integration Tests (Full Workflow)

**Test Case 1: PR with matching dashboard branch**
- Create PR in tyk with branch `test-matching-branch`
- Create matching branch in tyk-analytics
- Push PR, trigger workflow
- **Expected:** Uses gromit policy, no build, tests pass

**Test Case 2: PR without branch, ECR image exists**
- Create PR in tyk
- Pre-build and push dashboard image with PR commit SHA
- Push PR, trigger workflow
- **Expected:** Uses ECR image, no build, tests pass

**Test Case 3: PR without branch or image**
- Create PR in tyk (no matching dashboard branch)
- Ensure no ECR image exists with commit SHA
- Push PR, trigger workflow
- **Expected:** Builds dashboard, uses new image, tests pass

**Test Case 4: Push to master**
- Push commit to master
- **Expected:** Uses gromit policy for master, no build

**Test Case 5: Release tag**
- Create release tag v5.6.0
- **Expected:** Existing release workflow unchanged

### Validation Checklist

- [ ] All existing PRs continue to work (backward compatibility)
- [ ] New PRs with matching branches work (Scenario 1)
- [ ] New PRs without branches build correctly (Scenario 3)
- [ ] Dashboard built with correct gateway version
- [ ] Tests run successfully with custom dashboard
- [ ] ECR images are tagged correctly
- [ ] Workflow logs are clear and informative
- [ ] No secrets leaked in logs
- [ ] Performance impact is acceptable

---

## 🚨 Risks & Mitigations

### Risk 1: Build Failures
**Impact:** CI blocked, PR can't be merged
**Mitigation:**
- Extensive testing before rollout
- Fallback: temporarily disable auto-build, require manual dashboard branches
- Monitor build success rate

### Risk 2: Performance Degradation
**Impact:** CI takes significantly longer
**Mitigation:**
- Aggressive caching (go modules, Docker layers)
- Build only when necessary (3 strategy levels)
- Monitor average CI duration

### Risk 3: ECR Storage Costs
**Impact:** Many built images consuming storage
**Mitigation:**
- ECR lifecycle policy: delete SHA-tagged images after 30 days
- Delete untagged images after 7 days
- Monitor ECR storage usage

### Risk 4: Permission Issues
**Impact:** Can't push to ECR, build fails
**Mitigation:**
- Verify IAM role permissions before rollout
- Test push to tyk-analytics ECR repository
- Document required permissions

### Risk 5: Go Dependency Issues
**Impact:** `go get` fails for specific commit
**Mitigation:**
- Ensure tyk commits are accessible
- Configure GOPRIVATE correctly
- Use ORG_GH_TOKEN for private repo access

---

## 📝 Documentation Updates Needed

1. **For Developers (tyk repo):**
   - Update CONTRIBUTING.md with new workflow behavior
   - Explain when dashboard builds vs. uses gromit
   - How to create matching dashboard branches

2. **For CI/CD (internal docs):**
   - Troubleshooting guide for build failures
   - How to manually trigger dashboard build
   - ECR cleanup procedures

3. **For github-actions:**
   - Update env-up action README
   - Document dashboard_image input parameter
   - Add usage examples

---

## ✅ Ready to Implement

### Prerequisites (ALL VERIFIED ✅)
- [x] Dashboard image variable name: `tyk_analytics_image`
- [x] tyk-analytics build process understood
- [x] Gateway dependency management verified
- [x] ECR repository exists
- [x] IAM permissions confirmed (same role for both repos)

### Implementation Order

1. **Phase 1: Modify github-actions**
   - Add `dashboard_image` input to env-up action
   - Test in isolation
   - Merge to main

2. **Phase 2: Add jobs to tyk workflow**
   - Add `resolve-dashboard-image` job
   - Add `build-dashboard-image` job
   - Modify `api-tests` job
   - Test with draft PR

3. **Phase 3: Testing & Validation**
   - Run all test scenarios
   - Verify backward compatibility
   - Monitor performance

4. **Phase 4: Rollout**
   - Merge to tyk repository
   - Monitor first few PRs
   - Document any issues

---

## 🎯 Next Actions

**Immediate:**
1. Review this implementation plan
2. Approve approach and modifications
3. Start with Phase 1 (github-actions modification)

**Questions to answer:**
- [ ] Do we want to proceed with this implementation?
- [ ] Any concerns about the build-in-tyk approach?
- [ ] Should we add manual workflow_dispatch option?
- [ ] Any additional security considerations?

---

**Status:** ✅ Complete analysis, ready for implementation
**Confidence:** High - all key components verified
**Risk Level:** Low-Medium - well-understood changes with fallbacks
