# ACS Deployment Chart

Deploys **Red Hat Advanced Cluster Security for Kubernetes (RHACS)** via the RHACS Operator by creating the `Central` and optionally `SecuredCluster` custom resources. Aligned with [RHACS 4.9 Installing on Red Hat OpenShift](https://docs.redhat.com/en/documentation/red_hat_advanced_cluster_security_for_kubernetes/4.9/html/installing/installing-rhacs-on-red-hat-openshift).

## Prerequisites

- OpenShift 4.12 or later.
- RHACS Operator installed in the **rhacs-operator** namespace (via values-hub). Central and SecuredCluster CRs must be created in a **dedicated** namespace (recommended: **stackrox**), not in the operator namespace.

## Enabling ACS in the pattern

1. In **values-hub.yaml**:
   - Uncomment the `rhacs-operator` entry under `clusterGroup.namespaces` (Operator install namespace).
   - Uncomment the `rhacs-operator` entry under `clusterGroup.subscriptions`.
   - Uncomment the `stackrox` namespace entry under `clusterGroup.namespaces` (for Central and SecuredCluster CRs).
   - Uncomment the `acs-deployment` entry under `clusterGroup.applications` (namespace: **stackrox**).

2. Sync the hub application. The Operator installs in `rhacs-operator`; this chart creates the `Central` CR in `stackrox`. After Central is running, get the admin password and portal URL (see [Verifying Central installation](https://docs.redhat.com/en/documentation/red_hat_advanced_cluster_security_for_kubernetes/4.9/html/installing/installing-rhacs-on-red-hat-openshift#verify-central-installation-operator)), then generate an init bundle or Cluster Registration Secret (CRS) for secured clusters.

3. (Optional) To secure the hub cluster with RHACS (see [Installing secured cluster services](https://docs.redhat.com/en/documentation/red_hat_advanced_cluster_security_for_kubernetes/4.9/html/installing/installing-rhacs-on-red-hat-openshift#install-secured-cluster-ocp)):
   - Generate an init bundle (or CRS) from the Central UI or `roxctl`, and apply it to the **stackrox** namespace.
   - Set `acs.securedCluster.enabled: true` (e.g. via application overrides). SecuredCluster must be in the same namespace as Central when on the same cluster.

## Chart values

| Value | Description | Default |
|-------|-------------|---------|
| `acs.namespace` | Namespace for Central and SecuredCluster CRs (use a dedicated namespace, e.g. stackrox) | `stackrox` |
| `acs.crdApiVersion` | CRD apiVersion for Central/SecuredCluster | `platform.stackrox.io/v1alpha1` |
| `acs.central.enabled` | Deploy the Central CR (management plane) | `true` |
| `acs.central.name` | Name of the Central custom resource | `central` |
| `acs.central.spec` | Optional Central spec overrides (exposure, persistence, etc.) | `{}` |
| `acs.securedCluster.enabled` | Deploy a SecuredCluster CR for this cluster | `false` |
| `acs.securedCluster.name` | Name of the SecuredCluster custom resource | `secured-cluster-hub` |
| `acs.securedCluster.clusterName` | **Required when enabled:** unique cluster name in the RHACS portal (cannot be changed after create) | `""` |
| `acs.securedCluster.spec` | Optional SecuredCluster spec overrides (e.g. `centralEndpoint` for remote clusters) | `{}` |

To expose Central via an OpenShift route, use an override such as:
`acs.central.spec` → `central.exposure.route.enabled: true` (see [Central configuration options](https://docs.redhat.com/en/documentation/red_hat_advanced_cluster_security_for_kubernetes/4.9/html/installing/installing-rhacs-on-red-hat-openshift#central-configuration-options-operator)).

## References

- [Installing RHACS on Red Hat OpenShift (4.9)](https://docs.redhat.com/en/documentation/red_hat_advanced_cluster_security_for_kubernetes/4.9/html/installing/installing-rhacs-on-red-hat-openshift) — install Central, init bundle/CRS, SecuredCluster
- [Install Central using the Operator](https://docs.redhat.com/en/documentation/red_hat_advanced_cluster_security_for_kubernetes/4.9/html/installing/installing-rhacs-on-red-hat-openshift#install-central-ocp)
- [Installing secured cluster services for RHACS on Red Hat OpenShift](https://docs.redhat.com/en/documentation/red_hat_advanced_cluster_security_for_kubernetes/4.9/html/installing/installing-rhacs-on-red-hat-openshift#install-secured-cluster-ocp)
