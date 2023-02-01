.PHONY: import

import:
	terraform import module.$(REPO).github_repository.repository $(REPO)
	terraform import module.$(REPO).github_branch.default $(REPO):$(BRANCH)
	terraform import module.$(REPO).github_branch_default.default $(REPO)

fixed_import_protection:
	terraform import 'module.tyk.github_branch.release_branches["master"]' tyk:master
	terraform import 'module.tyk-analytics.github_branch.release_branches["master"]' tyk-analytics:master
	terraform import 'module.tyk-analytics-ui.github_branch.release_branches["master"]' tyk-analytics-ui:master
	terraform import 'module.tyk-pump.github_branch.release_branches["master"]' tyk-pump:master
	terraform import 'module.tyk-identity-broker.github_branch.release_branches["master"]' tyk-identity-broker:master
	terraform import 'module.tyk-sink.github_branch.release_branches["master"]' tyk-sink:master
	terraform import 'module.portal.github_branch.release_branches["master"]' portal:master
	terraform import 'module.tyk.github_branch_protection.automerge["master"]' tyk:master
	terraform import 'module.tyk-analytics.github_branch_protection.automerge["master"]' tyk-analytics:master
	terraform import 'module.tyk-analytics-ui.github_branch_protection.automerge["master"]' tyk-analytics-ui:master
	terraform import 'module.tyk-pump.github_branch_protection.automerge["master"]' tyk-pump:master
	terraform import 'module.tyk-identity-broker.github_branch_protection.automerge["master"]' tyk-identity-broker:master
	terraform import 'module.tyk.github_branch.release_branches["release-4"]' tyk:release-4
	terraform import 'module.tyk-analytics.github_branch.release_branches["release-4"]' tyk-analytics:release-4
	terraform import 'module.tyk-analytics-ui.github_branch.release_branches["release-4"]' tyk-analytics-ui:release-4

validate:
	terraform fmt
	terraform validate
	terraform fmt -recursive ../../../modules

clean:
	rm -rf ./.terraform*
