#!/usr/bin/env bash
set -eu

get_abs_filename() {
  # $1 : relative filename
  echo "$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
}

SCRIPT=$(get_abs_filename "$0")
SCRIPTPATH=$(dirname "${SCRIPT}")
COMMONPATH=$(dirname "${SCRIPTPATH}")
PATTERNPATH=$(dirname "${COMMONPATH}")

PATTERN_NAME=${1:-$(basename "`pwd`")}
SECRETS_BACKING_STORE="$($SCRIPTPATH/determine-secretstore-backend.sh)"

EXTRA_PLAYBOOK_OPTS="${EXTRA_PLAYBOOK_OPTS:-}"

# Run the main secrets processing Ansible playbook
# This now also handles:
# - Creating <prefix>-secret policies for custom vaultPrefixes
# - Updating hub-role with all policies
ansible-playbook -e pattern_name="${PATTERN_NAME}" -e pattern_dir="${PATTERNPATH}" -e secrets_backing_store="${SECRETS_BACKING_STORE}" ${EXTRA_PLAYBOOK_OPTS} "rhvp.cluster_utils.process_secrets"

# ==============================================================================
# JWT Auth Policy Setup (for SPIFFE workload identity)
# ==============================================================================
# The VP framework Ansible handles K8s auth policies automatically.
# This section creates additional JWT auth policies defined in values-hub.yaml
# for SPIFFE-based workload identity (e.g., qtodo-secrets, rhtpa-secrets).
# ==============================================================================

MAIN_CLUSTERGROUP_FILE="${PATTERNPATH}/values-$(${SCRIPTPATH}/determine-main-clustergroup.sh).yaml"

if [ ! -f "${MAIN_CLUSTERGROUP_FILE}" ]; then
    echo "No main clustergroup file found, skipping JWT policy setup"
    exit 0
fi

# Check if there are JWT policies defined
JWT_POLICIES=$(yq '.clusterGroup.applications.vault.policies[].name' "${MAIN_CLUSTERGROUP_FILE}" 2>/dev/null || true)

if [ -z "${JWT_POLICIES}" ]; then
    echo "No JWT policies found in ${MAIN_CLUSTERGROUP_FILE}, skipping JWT policy setup"
    exit 0
fi

# Check if Vault pod is running
VAULT_STATUS=$(oc get pod vault-0 -n vault -o jsonpath='{.status.phase}' 2>/dev/null || echo "NotFound")
if [ "${VAULT_STATUS}" != "Running" ]; then
    echo "WARNING: Vault pod is not running (status: ${VAULT_STATUS})"
    echo "Skipping JWT policy setup."
    exit 0
fi

# Check if Vault is unsealed
if ! oc exec -n vault vault-0 -- vault status 2>/dev/null | grep -q "Sealed.*false"; then
    echo "WARNING: Vault is sealed or not ready"
    echo "Skipping JWT policy setup."
    exit 0
fi

echo ""
echo "=== JWT Auth Policy Setup ==="
echo "Creating JWT auth policies from values-hub.yaml..."

for policy_name in ${JWT_POLICIES}; do
    policy_content=$(yq ".clusterGroup.applications.vault.policies[] | select(.name == \"${policy_name}\") | .policy" "${MAIN_CLUSTERGROUP_FILE}" 2>/dev/null || true)
    if [ -n "${policy_content}" ] && [ "${policy_content}" != "null" ]; then
        echo "  Creating policy: ${policy_name}"
        echo "${policy_content}" | oc exec -n vault vault-0 -i -- vault policy write "${policy_name}" - 2>/dev/null || echo "    WARNING: Failed to create ${policy_name}"
    fi
done

echo ""
echo "=== JWT Auth Policy Setup Complete ==="
