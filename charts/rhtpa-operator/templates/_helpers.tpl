{{/*
Expand the name of the chart.
*/}}
{{- define "rhtpa-operator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "rhtpa-operator.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "rhtpa-operator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "rhtpa-operator.labels" -}}
helm.sh/chart: {{ include "rhtpa-operator.chart" . }}
{{ include "rhtpa-operator.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "rhtpa-operator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "rhtpa-operator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Generate the Keycloak OIDC Issuer URL
This evaluates any template variables (like {{ $.Values.global.clusterDomain }})
and appends the realm name.
*/}}
{{- define "rhtpa-operator.keycloakOIDCIssuer" -}}
{{- $keycloakUrl := tpl .Values.rhtpa.zeroTrust.keycloak.url . -}}
{{- printf "%s/realms/%s" $keycloakUrl .Values.rhtpa.zeroTrust.keycloak.realm -}}
{{- end }}

