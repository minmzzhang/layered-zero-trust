{{/*
Expand the name of the chart.
*/}}
{{- define "ztvp-certificates.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "ztvp-certificates.fullname" -}}
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
{{- define "ztvp-certificates.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "ztvp-certificates.labels" -}}
helm.sh/chart: {{ include "ztvp-certificates.chart" . }}
{{ include "ztvp-certificates.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "ztvp-certificates.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ztvp-certificates.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Service account name
*/}}
{{- define "ztvp-certificates.serviceAccountName" -}}
{{- printf "%s-ca-extractor" (include "ztvp-certificates.fullname" .) }}
{{- end }}

{{/*
ACM hub template for reading ConfigMap data
Usage: include "ztvp-certificates.acmHubFromConfigMap" (dict "namespace" "openshift-config" "configmap" "ztvp-trusted-ca" "key" "tls-ca-bundle.pem")
Outputs: {{hub fromConfigMap "namespace" "configmap" "key" | autoindent hub}}
*/}}
{{- define "ztvp-certificates.acmHubFromConfigMap" -}}
{{- printf "{{hub fromConfigMap \"%s\" \"%s\" \"%s\" | autoindent hub}}" .namespace .configmap .key }}
{{- end }}

