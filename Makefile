.PHONY: default
default: help

.PHONY: help
##@ Pattern tasks

# No need to add a comment here as help is described in common/
help:
	@make -f common/Makefile MAKEFILE_LIST="Makefile common/Makefile" help

%:
	make -f common/Makefile $*

.PHONY: install
install: operator-deploy post-install ## installs the pattern and loads the secrets
	@echo "Installed"

.PHONY: wait-mcp
wait-mcp: ## Wait for MachineConfigPool rollout (skipped on HCP)
	@if oc get mcp/master >/dev/null 2>&1; then \
		echo "MachineConfigPool found — waiting for rollout to complete..."; \
		oc wait mcp/master --for=condition=Updated --timeout=600s; \
	else \
		echo "No MachineConfigPool — skipping (HCP or managed environment)"; \
	fi

.PHONY: post-install
post-install: ## Post-install tasks
	make load-secrets
	make wait-mcp
	make vault-config-jwt
	@echo "Done"

.PHONY: test
test:
	@make -f common/Makefile PATTERN_OPTS="-f values-global.yaml -f values-hub.yaml" test
