#!/usr/bin/env bash
# Configure Vault JWT auth mounts for spoke clusters
# Allows spoke clusters to authenticate to hub Vault using their local SPIRE OIDC provider
set -e
set -o pipefail

# Determine the pattern directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATTERN_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
VALUES_FILE="${PATTERN_DIR}/values-hub.yaml"

echo "==========================================="
echo "Vault Spoke Cluster JWT Configuration"
echo "==========================================="
echo ""
echo "Pattern directory: ${PATTERN_DIR}"
echo "Values file: ${VALUES_FILE}"
echo ""

if [ ! -f "$VALUES_FILE" ]; then
    echo "ERROR: values-hub.yaml not found: $VALUES_FILE"
    exit 1
fi

# Get hub cluster domain from values
HUB_CLUSTER_DOMAIN=$(yq '.global.clusterDomain' "$VALUES_FILE")
echo "Hub cluster domain: $HUB_CLUSTER_DOMAIN"

# Determine kubeconfig - align with validated patterns standard approach
# Priority: 1) KUBECONFIG env var (standard), 2) Current oc context
if [ -n "${KUBECONFIG:-}" ]; then
    echo "Using KUBECONFIG: $KUBECONFIG"
    # Verify connection to hub cluster
    CURRENT_CLUSTER=$(oc config current-context 2>/dev/null || echo "unknown")
    echo "Current context: $CURRENT_CLUSTER"
    echo "Expected hub domain: $HUB_CLUSTER_DOMAIN"
else
    echo "Using current oc context (no KUBECONFIG set)"
    CURRENT_CLUSTER=$(oc config current-context 2>/dev/null || echo "unknown")
    echo "Current context: $CURRENT_CLUSTER"
    echo ""
    echo "NOTE: Ensure you are connected to the hub cluster"
    echo "  Expected domain: $HUB_CLUSTER_DOMAIN"
    echo ""
    echo "To explicitly set hub cluster kubeconfig:"
    echo "  export KUBECONFIG=~/.kube/kubeconfig-ztvp-hub"
    echo "  make vault-config-spoke-jwt"
fi

echo ""

# Read spoke cluster configuration from values-hub.yaml
SPOKE_COUNT=$(yq '.clusterGroup.applications.vault.spokeClusters | length' "$VALUES_FILE")

if [ "$SPOKE_COUNT" = "0" ] || [ "$SPOKE_COUNT" = "null" ]; then
    echo "No spoke clusters configured in values-hub.yaml"
    echo "Add spoke clusters under: clusterGroup.applications.vault.spokeClusters"
    exit 0
fi

echo "Found $SPOKE_COUNT spoke cluster(s) in configuration"
echo ""

VAULT_NAMESPACE="vault"
VAULT_POD="vault-0"

echo "Checking Vault status..."
if ! oc get pod -n "$VAULT_NAMESPACE" "$VAULT_POD" >/dev/null 2>&1; then
    echo "ERROR: Vault pod not found in namespace $VAULT_NAMESPACE"
    echo "Ensure you are connected to the hub cluster"
    exit 1
fi

echo "Vault is running"
echo ""

# Track success/failure for summary
CONFIGURED_SPOKES=()
FAILED_SPOKES=()

# Loop through each spoke cluster configuration
for i in $(seq 0 $((SPOKE_COUNT - 1))); do
    spoke_name=$(yq ".clusterGroup.applications.vault.spokeClusters[$i].name" "$VALUES_FILE")
    jwt_mount=$(yq ".clusterGroup.applications.vault.spokeClusters[$i].jwtMount" "$VALUES_FILE")
    oidc_url=$(yq ".clusterGroup.applications.vault.spokeClusters[$i].oidcDiscoveryUrl" "$VALUES_FILE")
    
    echo "==========================================="
    echo "Configuring Spoke: $spoke_name"
    echo "JWT Mount: $jwt_mount"
    echo "OIDC URL: $oidc_url"
    echo "==========================================="
    
    # Check if mount exists
    echo "Checking if JWT mount '$jwt_mount' exists..."
    MOUNT_EXISTS=$(oc exec -n "$VAULT_NAMESPACE" "$VAULT_POD" -- \
        vault auth list -format=json 2>/dev/null | jq -r "has(\"${jwt_mount}/\")")
    
    if [ "$MOUNT_EXISTS" = "true" ]; then
        echo "JWT mount '$jwt_mount' already exists"
        
        # Check if config is already correct
        # Note: vault read returns non-zero if config doesn't exist, so we need to handle that
        CURRENT_OIDC_URL=$(oc exec -n "$VAULT_NAMESPACE" "$VAULT_POD" -- \
            vault read "auth/${jwt_mount}/config" -format=json 2>/dev/null | jq -r '.data.oidc_discovery_url // empty' || echo "")
        
        if [ -n "$CURRENT_OIDC_URL" ] && [ "$CURRENT_OIDC_URL" = "$oidc_url" ]; then
            echo "JWT mount '$jwt_mount' is already configured correctly"
            CONFIG_NEEDED=false
        else
            if [ -z "$CURRENT_OIDC_URL" ]; then
                echo "JWT mount '$jwt_mount' exists but is not configured"
            else
                echo "JWT mount '$jwt_mount' needs reconfiguration"
                echo "  Current OIDC URL: $CURRENT_OIDC_URL"
                echo "  Desired OIDC URL: $oidc_url"
            fi
            CONFIG_NEEDED=true
        fi
    else
        echo "Enabling JWT mount '$jwt_mount'..."
        oc exec -n "$VAULT_NAMESPACE" "$VAULT_POD" -- \
            vault auth enable -path="$jwt_mount" jwt
        echo "JWT mount enabled"
        CONFIG_NEEDED=true
    fi
    
    # Configure JWT auth only if needed
    if [ "$CONFIG_NEEDED" = "true" ]; then
        echo "Configuring JWT auth for '$jwt_mount'..."
        
        # Fetch CA certificate from OIDC discovery URL for TLS verification
        echo "  Fetching CA certificate from spoke OIDC provider..."
        OIDC_HOSTNAME=$(echo "$oidc_url" | sed 's|https://||' | sed 's|http://||' | cut -d'/' -f1)
        
        # Extract CA certificate (2nd cert in chain) from TLS connection
        CA_CERT=$(echo | openssl s_client -showcerts -servername "$OIDC_HOSTNAME" -connect "$OIDC_HOSTNAME:443" 2>/dev/null | \
            awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/{if(/BEGIN CERTIFICATE/){i++}if(i==2){print}}')
        
        if [ -z "$CA_CERT" ]; then
            echo "  WARNING: Could not fetch CA certificate"
            echo "  Attempting configuration without CA cert..."
            if ! oc exec -n "$VAULT_NAMESPACE" "$VAULT_POD" -- \
                vault write "auth/${jwt_mount}/config" \
                oidc_discovery_url="$oidc_url" \
                default_role="image-discovery" 2>&1; then
                echo "ERROR: Failed to configure JWT auth for '$jwt_mount'"
                echo "OIDC URL: $oidc_url"
                echo ""
                echo "Troubleshooting:"
                echo "  1. Verify spoke cluster's SPIRE OIDC route is accessible from hub"
                echo "  2. Test: oc exec -n vault vault-0 -- curl -k $oidc_url/.well-known/openid-configuration"
                echo "  3. Check TLS certificate and CA trust"
                echo ""
                echo "Continuing with remaining configuration..."
                echo ""
                continue
            fi
        else
            echo "  CA certificate fetched successfully"
            # Configure with CA certificate for proper TLS verification
            if ! oc exec -n "$VAULT_NAMESPACE" "$VAULT_POD" -- \
                vault write "auth/${jwt_mount}/config" \
                oidc_discovery_url="$oidc_url" \
                oidc_discovery_ca_pem="$CA_CERT" \
                default_role="image-discovery" 2>&1; then
                echo "ERROR: Failed to configure JWT auth for '$jwt_mount'"
                echo "Continuing with remaining configuration..."
                echo ""
                continue
            fi
        fi
        echo "JWT auth configured successfully"
    fi
    
    # Verify JWT mount is properly configured before creating roles
    echo "Verifying JWT mount configuration..."
    OIDC_CONFIGURED=$(oc exec -n "$VAULT_NAMESPACE" "$VAULT_POD" -- \
        vault read "auth/${jwt_mount}/config" -format=json 2>/dev/null | jq -r '.data.oidc_discovery_url // empty' || echo "")
    
    if [ -z "$OIDC_CONFIGURED" ]; then
        echo "ERROR: JWT mount '$jwt_mount' is not properly configured"
        echo "Cannot create roles without a configured JWT mount"
        echo "Skipping role creation for spoke: $spoke_name"
        echo ""
        FAILED_SPOKES+=("$spoke_name")
        continue
    fi
    
    echo "JWT mount verified - OIDC URL: $OIDC_CONFIGURED"
    echo ""
    
    # Create roles for this spoke cluster
    role_count=$(yq ".clusterGroup.applications.vault.spokeClusters[$i].roles | length" "$VALUES_FILE")
    
    for j in $(seq 0 $((role_count - 1))); do
        role_name=$(yq ".clusterGroup.applications.vault.spokeClusters[$i].roles[$j].name" "$VALUES_FILE")
        role_audience=$(yq ".clusterGroup.applications.vault.spokeClusters[$i].roles[$j].audience" "$VALUES_FILE")
        role_policies=$(yq ".clusterGroup.applications.vault.spokeClusters[$i].roles[$j].policies | join(\",\")" "$VALUES_FILE")
        role_ttl=$(yq ".clusterGroup.applications.vault.spokeClusters[$i].roles[$j].ttl // \"86400\"" "$VALUES_FILE")
        
        # Check if role already exists
        # Note: vault read returns non-zero if role doesn't exist, handle gracefully
        ROLE_EXISTS=$(oc exec -n "$VAULT_NAMESPACE" "$VAULT_POD" -- \
            vault read "auth/${jwt_mount}/role/${role_name}" -format=json 2>/dev/null || echo "")
        
        if [ -n "$ROLE_EXISTS" ]; then
            echo "  Role $role_name already exists - updating..."
        else
            echo "  Creating role: $role_name..."
        fi
        
        oc exec -n "$VAULT_NAMESPACE" "$VAULT_POD" -- \
            vault write "auth/${jwt_mount}/role/${role_name}" \
            role_type="jwt" \
            bound_audiences="$role_audience" \
            token_policies="$role_policies" \
            token_ttl="$role_ttl" \
            user_claim="sub"
        
        if [ -n "$ROLE_EXISTS" ]; then
            echo "  Role $role_name updated"
        else
            echo "  Role $role_name created"
        fi
    done
    
    # Verify configuration
    echo "Verifying configuration..."
    oc exec -n "$VAULT_NAMESPACE" "$VAULT_POD" -- \
        vault read "auth/${jwt_mount}/config" -format=json | jq -r '.data | {oidc_discovery_url, default_role}'
    
    # Mark this spoke as successfully configured
    CONFIGURED_SPOKES+=("$spoke_name")
    
    echo ""
done

echo "==========================================="
echo "Configuration Complete!"
echo "==========================================="
echo ""

# Print summary
CONFIGURED_COUNT=${#CONFIGURED_SPOKES[@]}
FAILED_COUNT=${#FAILED_SPOKES[@]}

if [ "$CONFIGURED_COUNT" -gt 0 ]; then
    echo "Successfully configured spoke clusters ($CONFIGURED_COUNT):"
    for spoke in "${CONFIGURED_SPOKES[@]}"; do
        echo "  - $spoke"
    done
    echo ""
fi

if [ "$FAILED_COUNT" -gt 0 ]; then
    echo "Failed to configure spoke clusters ($FAILED_COUNT):"
    for spoke in "${FAILED_SPOKES[@]}"; do
        echo "  - $spoke"
    done
    echo ""
    echo "Review errors above for troubleshooting details."
    exit 1
fi

echo "All JWT auth mounts configured successfully."
echo "Spoke clusters can now authenticate to hub Vault using their SPIRE JWTs."
echo ""

