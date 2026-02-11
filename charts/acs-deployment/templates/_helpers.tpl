{{/*
Expand the name of the chart.
*/}}
{{- define "acs-deployment.name" -}}
{{- default .Chart.Name .Values.nameOverride }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "acs-deployment.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "acs-deployment.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "acs-deployment.labels" -}}
helm.sh/chart: {{ include "acs-deployment.chart" . }}
app.kubernetes.io/name: {{ include "acs-deployment.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}
