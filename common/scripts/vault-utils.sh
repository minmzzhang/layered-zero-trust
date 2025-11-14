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
MAIN_CLUSTERGROUP_FILE="./values-$(common/scripts/determine-main-clustergroup.sh).yaml"

# Parse arguments
if [ $# -lt 1 ]; then
  echo "Specify at least the command ($#): $*"
  exit 1
fi

TASK="${1}"
PATTERN_NAME=${2:-$(basename "`pwd`")}

if [ -z "${TASK}" ]; then
	echo "Task is unset"
	exit 1
fi

EXTRA_PLAYBOOK_OPTS="${EXTRA_PLAYBOOK_OPTS:-}"

if [ "$(yq ".clusterGroup.applications.vault.jwt.enabled // \"false\"" "${MAIN_CLUSTERGROUP_FILE}")" == "true" ]; then
  OCP_DOMAIN="$(oc get dns cluster -o jsonpath='{.spec.baseDomain}')"
  OIDC_DISCOVERY_URL="$(yq ".clusterGroup.applications.vault.jwt.oidcDiscoveryUrl" "${MAIN_CLUSTERGROUP_FILE}" | sed "s/{{ \$.Values.global.clusterDomain }}/${OCP_DOMAIN}/g")"
  JWT_ROLES="$(yq -o json ".clusterGroup.applications.vault.jwt.roles" "${MAIN_CLUSTERGROUP_FILE}" | jq -rc | sed "s/{{ \$.Values.global.clusterDomain }}/${OCP_DOMAIN}/g")"

  if [ "${OIDC_DISCOVERY_URL}" == "null" ] || [ "${JWT_ROLES}" == "null" ] || [ "${JWT_ROLES}" == "[]" ]; then
    echo "Vault JWT config is disabled because of missing required fields"
    VAULT_JWT_CONFIG="false"
    echo "OIDC_DISCOVERY_URL: ${OIDC_DISCOVERY_URL}"
    echo "JWT_ROLES: ${JWT_ROLES}"
    echo "Vault JWT config is disabled"
  else
    VAULT_JWT_CONFIG="true"
    echo "Vault JWT config is enabled"
  fi

else
  VAULT_JWT_CONFIG="false"
  echo "Vault JWT config is disabled"
fi

ansible-playbook -t "${TASK}" \
  -e pattern_name="${PATTERN_NAME}" \
  -e pattern_dir="${PATTERNPATH}" \
  -e vault_jwt_config="${VAULT_JWT_CONFIG}" \
  -e oidc_discovery_url="${OIDC_DISCOVERY_URL:-}" \
  -e vault_jwt_roles="${JWT_ROLES:-'[]'}" \
  ${EXTRA_PLAYBOOK_OPTS} "rhvp.cluster_utils.vault"
