# PRs Merged Without Jira ID (April 14-21, 2026)

PRs merged across all Tyk repos without a `TT-XXXXX` Jira ticket association.
Generated on 2026-04-21.

## Suggested Jira Associations

| Category | Suggested Ticket | Description |
|---|---|---|
| Docker nonroot / runAsUser / chown | TT-16950 | Docker image backward compatibility with helm runAsUser: 1000 |
| CVE fixes (go-jose, otel, goxmldsig, pgx) | TT-16932 | Critical CVE fixes |
| FIPS base image / plugin compiler | TT-16951 | FIPS 140-3 compliance |
| CI/CD fixes (dep-guard, labeled trigger, jira linter) | TT-17002 | CI/CD pipeline fixes |
| Go 1.25 compatibility (cert_test, OTel struct, dashboard builder) | TT-16342 | Go 1.25 upgrade |
| Dashboard resolver | TT-16950 | CI integration test infrastructure |
| Branch sync / backports | TT-16932 | Release branch maintenance |

---

## tyk

| PR | Branch | Title | Suggested Ticket |
|---|---|---|---|
| [#8120](https://github.com/TykTechnologies/tyk/pull/8120) | release-5.8.13 | fix: make middleware/bundles writable for plugin bundles | TT-16950 |
| [#8119](https://github.com/TykTechnologies/tyk/pull/8119) | release-5.8 | fix: make middleware/bundles writable for plugin bundles | TT-16950 |
| [#8118](https://github.com/TykTechnologies/tyk/pull/8118) | release-5.12.1 | fix: make middleware/bundles writable for plugin bundles | TT-16950 |
| [#8117](https://github.com/TykTechnologies/tyk/pull/8117) | release-5.12 | fix: make middleware/bundles writable for plugin bundles | TT-16950 |
| [#8116](https://github.com/TykTechnologies/tyk/pull/8116) | master | fix: make middleware/bundles writable for plugin bundles | TT-16950 |
| [#8112](https://github.com/TykTechnologies/tyk/pull/8112) | release-5.12.1 | fix: update test files for opentelemetry v0.0.25 struct layout | TT-16342 |
| [#8111](https://github.com/TykTechnologies/tyk/pull/8111) | release-5.12.1 | fix: update cert_test.go TLS error strings for Go 1.25 | TT-16342 |
| [#8110](https://github.com/TykTechnologies/tyk/pull/8110) | release-5.12 | fix: update cert_test.go TLS error strings for Go 1.25 | TT-16342 |
| [#8108](https://github.com/TykTechnologies/tyk/pull/8108) | release-5.12 | fix: bump grpc-gcp-go to v1.6.0 (build broken) | TT-16932 |
| [#8107](https://github.com/TykTechnologies/tyk/pull/8107) | release-5.12.1 | chore: update dependencies in go.mod and go.sum | TT-16932 |
| [#8106](https://github.com/TykTechnologies/tyk/pull/8106) | release-5.8.13 | fix: make Docker images backward compatible with runAsUser: 1000 | TT-16950 |
| [#8105](https://github.com/TykTechnologies/tyk/pull/8105) | release-5.8 | fix: make Docker images backward compatible with runAsUser: 1000 | TT-16950 |
| [#8104](https://github.com/TykTechnologies/tyk/pull/8104) | release-5.12.1 | fix: make Docker images backward compatible with runAsUser: 1000 | TT-16950 |
| [#8103](https://github.com/TykTechnologies/tyk/pull/8103) | release-5.12 | fix: make Docker images backward compatible with runAsUser: 1000 | TT-16950 |
| [#8102](https://github.com/TykTechnologies/tyk/pull/8102) | master | fix: make Docker images backward compatible with runAsUser: 1000 | TT-16950 |
| [#8101](https://github.com/TykTechnologies/tyk/pull/8101) | release-5.12.1 | fix: use Go 1.25 for dashboard builder step | TT-16342 |
| [#8099](https://github.com/TykTechnologies/tyk/pull/8099) | release-5.12 | fix: use Go 1.25 for dashboard builder step | TT-16342 |
| [#8098](https://github.com/TykTechnologies/tyk/pull/8098) | master | fix: use Go 1.25 for dashboard builder step | TT-16342 |
| [#8097](https://github.com/TykTechnologies/tyk/pull/8097) | release-5.12 | Merging to release-5.12: Update pump an storage to support pgx v5 (#8094) | TT-16932 |
| [#8096](https://github.com/TykTechnologies/tyk/pull/8096) | release-5.8 | Merging to release-5.8: Update pump an storage to support pgx v5 (#8095) | TT-16932 |
| [#8095](https://github.com/TykTechnologies/tyk/pull/8095) | release-5.8.13 | Update pump an storage to support pgx v5 | TT-16932 |
| [#8094](https://github.com/TykTechnologies/tyk/pull/8094) | release-5.12.1 | Update pump an storage to support pgx v5 | TT-16932 |
| [#8093](https://github.com/TykTechnologies/tyk/pull/8093) | master | Update pump an storage to support pgx v5 | TT-16932 |
| [#8092](https://github.com/TykTechnologies/tyk/pull/8092) | release-5.8 | [TT-16932] CVE fixes for release-5.8 | TT-16932 |
| [#8091](https://github.com/TykTechnologies/tyk/pull/8091) | release-5.12 | [TT-16932] CVE fixes for release-5.12 | TT-16932 |
| [#8089](https://github.com/TykTechnologies/tyk/pull/8089) | release-5.12.1 | fix: trigger release workflow on PR labeled event | TT-17002 |
| [#8088](https://github.com/TykTechnologies/tyk/pull/8088) | release-5.12 | fix: trigger release workflow on PR labeled event | TT-17002 |
| [#8087](https://github.com/TykTechnologies/tyk/pull/8087) | master | fix: trigger release workflow on PR labeled event | TT-17002 |
| [#8084](https://github.com/TykTechnologies/tyk/pull/8084) | release-5.12.1 | fix: prevent dep-guard from skipping plugin compiler build on push | TT-17002 |
| [#8083](https://github.com/TykTechnologies/tyk/pull/8083) | release-5.12 | fix: prevent dep-guard from skipping plugin compiler build on push | TT-17002 |
| [#8082](https://github.com/TykTechnologies/tyk/pull/8082) | master | fix: prevent dep-guard from skipping plugin compiler build on push | TT-17002 |
| [#8080](https://github.com/TykTechnologies/tyk/pull/8080) | release-5.8.13 | fix: upgrade Go to 1.25 on release-5.8.13 | TT-16342 |
| [#8077](https://github.com/TykTechnologies/tyk/pull/8077) | release-5.12.1 | fix: prevent dep-guard from skipping downstream jobs on push | TT-17002 |
| [#8076](https://github.com/TykTechnologies/tyk/pull/8076) | release-5.12 | fix: prevent dep-guard from skipping downstream jobs on push | TT-17002 |
| [#8075](https://github.com/TykTechnologies/tyk/pull/8075) | master | fix: prevent dep-guard from skipping downstream jobs on push | TT-17002 |
| [#8078](https://github.com/TykTechnologies/tyk/pull/8078) | release-5.8 | fix: prevent dep-guard from skipping downstream jobs on push | TT-17002 |
| [#8074](https://github.com/TykTechnologies/tyk/pull/8074) | release-5.8.13 | fix: backport #7974 — validate middleware collapsed path fix | TT-16890 |
| [#8073](https://github.com/TykTechnologies/tyk/pull/8073) | release-5.8 | fix: backport #7974 — validate middleware collapsed path fix | TT-16890 |
| [#8072](https://github.com/TykTechnologies/tyk/pull/8072) | release-5.8.13 | fix: backport #7972 — validate request middleware regression | TT-16890 |
| [#8071](https://github.com/TykTechnologies/tyk/pull/8071) | release-5.8 | fix: backport #7972 — validate request middleware regression | TT-16890 |
| [#8070](https://github.com/TykTechnologies/tyk/pull/8070) | release-5.12.1 | fix: sync security hardening from release-5.12 (#7956) | TT-16950 |
| [#8069](https://github.com/TykTechnologies/tyk/pull/8069) | release-5.12 | fix: sync critical commits from release-5.12.1 | TT-16890 |
| [#8067](https://github.com/TykTechnologies/tyk/pull/8067) | release-5.12.1 | fix: backport #7974 — validate middleware collapsed path fix | TT-16890 |
| [#8065](https://github.com/TykTechnologies/tyk/pull/8065) | release-5.12 | fix: backport #7995 — fix tslib and npm ci in ci/tests/specs | TT-16966 |
| [#8064](https://github.com/TykTechnologies/tyk/pull/8064) | release-5.12.1 | fix: backport #7995 — fix tslib and policies schema | TT-16966 |
| [#8059](https://github.com/TykTechnologies/tyk/pull/8059) | release-5.12.1 | fix: update OTel test scenarios to match Go 1.25 attribute names | TT-16342 |
| [#8056](https://github.com/TykTechnologies/tyk/pull/8056) | release-5.12.1 | fix: dashboard resolver credential fix (release-5.12.1) | TT-16950 |
| [#8055](https://github.com/TykTechnologies/tyk/pull/8055) | release-5.12 | fix: dashboard resolver credential fix (release-5.12) | TT-16950 |
| [#8054](https://github.com/TykTechnologies/tyk/pull/8054) | master | fix: dashboard resolver credential fix (master) | TT-16950 |
| [#8053](https://github.com/TykTechnologies/tyk/pull/8053) | release-5.8 | fix: add jira-user-email to Jira linter workflow | TT-17002 |
| [#8052](https://github.com/TykTechnologies/tyk/pull/8052) | release-5.12.1 | fix: add jira-user-email to Jira linter workflow | TT-17002 |
| [#8051](https://github.com/TykTechnologies/tyk/pull/8051) | release-5.12 | fix: add jira-user-email to Jira linter workflow | TT-17002 |
| [#8049](https://github.com/TykTechnologies/tyk/pull/8049) | master | fix: add jira-user-email to Jira linter workflow | TT-17002 |
| [#8048](https://github.com/TykTechnologies/tyk/pull/8048) | release-5.12.1 | revert: undo incorrect OTel scenario update (PR #8042) | TT-16342 |
| [#8047](https://github.com/TykTechnologies/tyk/pull/8047) | release-5.12 | revert: undo incorrect OTel scenario update (PR #8041) | TT-16342 |
| [#8045](https://github.com/TykTechnologies/tyk/pull/8045) | release-5.12.1 | fix: dashboard resolver matches release branches | TT-16950 |
| [#8044](https://github.com/TykTechnologies/tyk/pull/8044) | release-5.12 | fix: dashboard resolver matches release branches | TT-16950 |
| [#8043](https://github.com/TykTechnologies/tyk/pull/8043) | master | fix: dashboard resolver matches release branches | TT-16950 |
| [#8042](https://github.com/TykTechnologies/tyk/pull/8042) | release-5.12.1 | fix: update OTel tracing test scenarios for Go 1.25 | TT-16342 |
| [#8041](https://github.com/TykTechnologies/tyk/pull/8041) | release-5.12 | fix: update OTel tracing test scenarios for Go 1.25 | TT-16342 |
| [#8040](https://github.com/TykTechnologies/tyk/pull/8040) | release-5.12.1 | fix: align plugin compiler Go version with gateway (1.25) | TT-16342 |
| [#8039](https://github.com/TykTechnologies/tyk/pull/8039) | release-5.12 | fix: align plugin compiler Go version with gateway (1.25) | TT-16342 |
| [#8034](https://github.com/TykTechnologies/tyk/pull/8034) | release-5.8.13 | Merging to release-5.8.13: fix: set nonroot ownership on application files | TT-16950 |
| [#8033](https://github.com/TykTechnologies/tyk/pull/8033) | release-5.8 | Merging to release-5.8: fix: set nonroot ownership on application files | TT-16950 |
| [#8032](https://github.com/TykTechnologies/tyk/pull/8032) | release-5.12.1 | Merging to release-5.12.1: fix: set nonroot ownership on application files | TT-16950 |
| [#8016](https://github.com/TykTechnologies/tyk/pull/8016) | release-5.12.1 | fix: use separate ECR repo for FIPS CI images | TT-16951 |
| [#8015](https://github.com/TykTechnologies/tyk/pull/8015) | release-5.12 | fix: use separate ECR repo for FIPS CI images | TT-16951 |
| [#8014](https://github.com/TykTechnologies/tyk/pull/8014) | master | fix: use separate ECR repo for FIPS CI images | TT-16951 |
| [#8013](https://github.com/TykTechnologies/tyk/pull/8013) | release-5.8 | fix: plugin compiler FIPS support + goplugin tag | TT-16951 |
| [#8012](https://github.com/TykTechnologies/tyk/pull/8012) | release-5.12.1 | fix: plugin compiler FIPS support + goplugin tag | TT-16951 |
| [#8011](https://github.com/TykTechnologies/tyk/pull/8011) | release-5.12 | fix: plugin compiler FIPS support + goplugin tag | TT-16951 |
| [#8010](https://github.com/TykTechnologies/tyk/pull/8010) | master | fix: plugin compiler FIPS support + goplugin tag | TT-16951 |

## tyk-analytics

| PR | Branch | Title | Suggested Ticket |
|---|---|---|---|
| [#5522](https://github.com/TykTechnologies/tyk-analytics/pull/5522) | release-5.12 | fix: bump grpc-gcp-go to v1.6.0 (build broken) | TT-16932 |
| [#5521](https://github.com/TykTechnologies/tyk-analytics/pull/5521) | release-5.12.1 | chore: update opentelemetry otlpmetrichttp dependency to v1.43.0 | TT-16932 |
| [#5519](https://github.com/TykTechnologies/tyk-analytics/pull/5519) | release-5.12.1 | fix: make Docker images backward compatible with runAsUser: 1000 | TT-16950 |
| [#5518](https://github.com/TykTechnologies/tyk-analytics/pull/5518) | release-5.12 | fix: make Docker images backward compatible with runAsUser: 1000 | TT-16950 |
| [#5517](https://github.com/TykTechnologies/tyk-analytics/pull/5517) | master | fix: make Docker images backward compatible with runAsUser: 1000 | TT-16950 |
| [#5511](https://github.com/TykTechnologies/tyk-analytics/pull/5511) | release-5.8.13 | fix: bump TIB to v1.7.1-rc2 (CVE-2026-33487) | TT-16932 |
| [#5510](https://github.com/TykTechnologies/tyk-analytics/pull/5510) | release-5.8 | fix: bump TIB to v1.7.1-rc2 (CVE-2026-33487) | TT-16932 |
| [#5509](https://github.com/TykTechnologies/tyk-analytics/pull/5509) | release-5.12.1 | fix: bump TIB to v1.7.1-rc2 (CVE-2026-33487) | TT-16932 |
| [#5508](https://github.com/TykTechnologies/tyk-analytics/pull/5508) | release-5.12 | fix: bump TIB to v1.7.1-rc2 (CVE-2026-33487) | TT-16932 |
| [#5507](https://github.com/TykTechnologies/tyk-analytics/pull/5507) | master | fix: bump TIB to v1.7.1-rc2 (CVE-2026-33487) | TT-16932 |
| [#5506](https://github.com/TykTechnologies/tyk-analytics/pull/5506) | release-5.8.13 | fix: CVE-2026-33487 — bump goxmldsig to v1.6.0 | TT-16932 |
| [#5505](https://github.com/TykTechnologies/tyk-analytics/pull/5505) | release-5.8 | fix: CVE-2026-33487 — bump goxmldsig to v1.6.0 | TT-16932 |
| [#5504](https://github.com/TykTechnologies/tyk-analytics/pull/5504) | release-5.12.1 | fix: CVE-2026-33487 — bump goxmldsig to v1.6.0 | TT-16932 |
| [#5503](https://github.com/TykTechnologies/tyk-analytics/pull/5503) | release-5.12 | fix: CVE-2026-33487 — bump goxmldsig to v1.6.0 | TT-16932 |
| [#5502](https://github.com/TykTechnologies/tyk-analytics/pull/5502) | master | fix: CVE-2026-33487 — bump goxmldsig to v1.6.0 | TT-16932 |
| [#5501](https://github.com/TykTechnologies/tyk-analytics/pull/5501) | release-5.8 | fix: update gorm fork to fix broken build | TT-16932 |
| [#5500](https://github.com/TykTechnologies/tyk-analytics/pull/5500) | release-5.8.13 | fix: update gorm fork to fix broken build | TT-16932 |
| [#5499](https://github.com/TykTechnologies/tyk-analytics/pull/5499) | release-5.12 | fix: update gorm fork to fix broken build | TT-16932 |
| [#5498](https://github.com/TykTechnologies/tyk-analytics/pull/5498) | release-5.12.1 | fix: update gorm fork to fix broken build | TT-16932 |
| [#5495](https://github.com/TykTechnologies/tyk-analytics/pull/5495) | release-5.8 | [TT-16932] CVE fixes for release-5.8 | TT-16932 |
| [#5494](https://github.com/TykTechnologies/tyk-analytics/pull/5494) | release-5.12 | [TT-16932] CVE fixes for release-5.12 | TT-16932 |
| [#5493](https://github.com/TykTechnologies/tyk-analytics/pull/5493) | release-5.12.1 | fix: trigger release workflow on PR labeled event | TT-17002 |
| [#5492](https://github.com/TykTechnologies/tyk-analytics/pull/5492) | release-5.12 | fix: trigger release workflow on PR labeled event | TT-17002 |
| [#5491](https://github.com/TykTechnologies/tyk-analytics/pull/5491) | master | fix: trigger release workflow on PR labeled event | TT-17002 |
| [#5490](https://github.com/TykTechnologies/tyk-analytics/pull/5490) | release-5.8.13 | fix: complete test framework backport from #5324 | TT-16890 |
| [#5489](https://github.com/TykTechnologies/tyk-analytics/pull/5489) | release-5.12 | fix: complete test framework backport from #5324 | TT-16890 |
| [#5488](https://github.com/TykTechnologies/tyk-analytics/pull/5488) | release-5.12.1 | fix: complete test framework backport from #5324 | TT-16890 |
| [#5486](https://github.com/TykTechnologies/tyk-analytics/pull/5486) | release-5.8.13 | fix: backport #5324 test helpers for oas_path_matching_test | TT-16890 |
| [#5485](https://github.com/TykTechnologies/tyk-analytics/pull/5485) | release-5.12.1 | fix: backport #5324 test helpers for oas_path_matching_test | TT-16890 |
| [#5484](https://github.com/TykTechnologies/tyk-analytics/pull/5484) | release-5.12 | fix: backport #5324 test helpers for oas_path_matching_test | TT-16890 |
| [#5483](https://github.com/TykTechnologies/tyk-analytics/pull/5483) | release-5.12.1 | fix: prevent dep-guard from skipping downstream jobs on push | TT-17002 |
| [#5482](https://github.com/TykTechnologies/tyk-analytics/pull/5482) | release-5.12 | fix: prevent dep-guard from skipping downstream jobs on push | TT-17002 |
| [#5481](https://github.com/TykTechnologies/tyk-analytics/pull/5481) | master | fix: prevent dep-guard from skipping downstream jobs on push | TT-17002 |
| [#5480](https://github.com/TykTechnologies/tyk-analytics/pull/5480) | release-5.8.13 | fix: backport Go 1.25, security hardening, deps to release-5.8.13 | TT-16342 |
| [#5479](https://github.com/TykTechnologies/tyk-analytics/pull/5479) | release-5.12.1 | fix: backport #5414 — integration tests | TT-16890 |
| [#5478](https://github.com/TykTechnologies/tyk-analytics/pull/5478) | release-5.8.13 | fix: backport #5414 — integration tests | TT-16890 |
| [#5477](https://github.com/TykTechnologies/tyk-analytics/pull/5477) | release-5.8 | fix: backport #5414 — integration tests | TT-16890 |
| [#5476](https://github.com/TykTechnologies/tyk-analytics/pull/5476) | release-5.12 | fix: backport #5414 — integration tests | TT-16890 |
| [#5475](https://github.com/TykTechnologies/tyk-analytics/pull/5475) | master | fix: add jira-user-email to Jira linter workflow | TT-17002 |

## tyk-pump

| PR | Branch | Title | Suggested Ticket |
|---|---|---|---|
| [#984](https://github.com/TykTechnologies/tyk-pump/pull/984) | release-1.14.1 | fix: make Docker images backward compatible with runAsUser: 1000 | TT-16950 |
| [#983](https://github.com/TykTechnologies/tyk-pump/pull/983) | release-1.14 | fix: make Docker images backward compatible with runAsUser: 1000 | TT-16950 |
| [#982](https://github.com/TykTechnologies/tyk-pump/pull/982) | master | fix: make Docker images backward compatible with runAsUser: 1000 | TT-16950 |
| [#981](https://github.com/TykTechnologies/tyk-pump/pull/981) | release-1.14.1 | Merging to release-1.14.1: Update gorm and storage deps (#977) | TT-16932 |
| [#976](https://github.com/TykTechnologies/tyk-pump/pull/976) | release-1.14.1 | fix: trigger release workflow on PR labeled event | TT-17002 |
| [#975](https://github.com/TykTechnologies/tyk-pump/pull/975) | release-1.14 | fix: trigger release workflow on PR labeled event | TT-17002 |
| [#974](https://github.com/TykTechnologies/tyk-pump/pull/974) | master | fix: trigger release workflow on PR labeled event | TT-17002 |
| [#973](https://github.com/TykTechnologies/tyk-pump/pull/973) | release-1.14.1 | fix: prevent dep-guard from skipping downstream jobs on push | TT-17002 |
| [#972](https://github.com/TykTechnologies/tyk-pump/pull/972) | release-1.14 | fix: prevent dep-guard from skipping downstream jobs on push | TT-17002 |
| [#971](https://github.com/TykTechnologies/tyk-pump/pull/971) | master | fix: prevent dep-guard from skipping downstream jobs on push | TT-17002 |
| [#968](https://github.com/TykTechnologies/tyk-pump/pull/968) | master | fix: add jira-user-email to Jira linter workflow | TT-17002 |

## tyk-sink

| PR | Branch | Title | Suggested Ticket |
|---|---|---|---|
| [#773](https://github.com/TykTechnologies/tyk-sink/pull/773) | master | fix: update gorm fork to support driver/postgres v1.5.0 | TT-16932 |
| [#772](https://github.com/TykTechnologies/tyk-sink/pull/772) | master | fix: make Docker images backward compatible with runAsUser: 1000 | TT-16950 |
| [#771](https://github.com/TykTechnologies/tyk-sink/pull/771) | master | [TT-16932] CVE fixes: otel/sdk | TT-16932 |
| [#770](https://github.com/TykTechnologies/tyk-sink/pull/770) | master | fix: trigger release workflow on PR labeled event | TT-17002 |
| [#769](https://github.com/TykTechnologies/tyk-sink/pull/769) | master | fix: prevent dep-guard from skipping downstream jobs on push | TT-17002 |
| [#768](https://github.com/TykTechnologies/tyk-sink/pull/768) | master | fix: add jira-user-email to Jira linter workflow | TT-17002 |
| [#764](https://github.com/TykTechnologies/tyk-sink/pull/764) | master | Fix CI and Dockerfile issues from PR 763 | TT-16951 |

## tyk-identity-broker

| PR | Branch | Title | Suggested Ticket |
|---|---|---|---|
| [#469](https://github.com/TykTechnologies/tyk-identity-broker/pull/469) | release-1.7.1 | fix: make Docker images backward compatible with runAsUser: 1000 | TT-16950 |
| [#468](https://github.com/TykTechnologies/tyk-identity-broker/pull/468) | release-1.7 | fix: make Docker images backward compatible with runAsUser: 1000 | TT-16950 |
| [#467](https://github.com/TykTechnologies/tyk-identity-broker/pull/467) | master | fix: make Docker images backward compatible with runAsUser: 1000 | TT-16950 |
| [#460](https://github.com/TykTechnologies/tyk-identity-broker/pull/460) | master | fix: add jira-user-email to Jira linter workflow | TT-17002 |

## portal

| PR | Branch | Title | Suggested Ticket |
|---|---|---|---|
| [#1873](https://github.com/TykTechnologies/portal/pull/1873) | master | fix: make Docker images backward compatible with runAsUser: 1000 | TT-16950 |
| [#1871](https://github.com/TykTechnologies/portal/pull/1871) | master | fix: add jira-user-email to Jira linter workflow | TT-17002 |

## gromit

| PR | Branch | Title | Suggested Ticket |
|---|---|---|---|
| [#454](https://github.com/TykTechnologies/gromit/pull/454) | master | fix: TUI prod-variations config | TT-17002 |

## tyk-analytics-ui

| PR | Branch | Title | Suggested Ticket |
|---|---|---|---|
| [#4328](https://github.com/TykTechnologies/tyk-analytics-ui/pull/4328) | release-5.12 | fix: dep-guard skip propagation + labeled trigger | TT-17002 |
| [#4327](https://github.com/TykTechnologies/tyk-analytics-ui/pull/4327) | release-5.11 | fix: dep-guard skip propagation + labeled trigger | TT-17002 |
| [#4326](https://github.com/TykTechnologies/tyk-analytics-ui/pull/4326) | release-5.8 | fix: dep-guard skip propagation + labeled trigger | TT-17002 |
| [#4325](https://github.com/TykTechnologies/tyk-analytics-ui/pull/4325) | release-5.3 | fix: dep-guard skip propagation + labeled trigger | TT-17002 |
| [#4324](https://github.com/TykTechnologies/tyk-analytics-ui/pull/4324) | master | fix: dep-guard skip propagation + labeled trigger | TT-17002 |

---

## Summary by Category

| Category | Ticket | PR Count |
|---|---|---|
| CVE fixes (go-jose, otel, goxmldsig, pgx, pgproto3, gorm) | TT-16932 | 32 |
| Docker nonroot / runAsUser / chown / writable bundles | TT-16950 | 25 |
| CI/CD fixes (dep-guard, labeled trigger, jira linter, TUI, dashboard resolver) | TT-17002 | 30 |
| FIPS compliance (plugin compiler, ECR repos) | TT-16951 | 8 |
| Go 1.25 compatibility (cert_test, OTel, dashboard builder) | TT-16342 | 14 |
| Validate request middleware backports | TT-16890 | 12 |
| tslib/npm ci fix backport | TT-16966 | 2 |
| **Total** | | **123** |
