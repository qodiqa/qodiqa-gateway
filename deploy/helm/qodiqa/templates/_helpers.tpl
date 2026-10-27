{{- define "qodiqa.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "qodiqa.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "qodiqa.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "qodiqa.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
topology: distributed
{{- end -}}

{{- define "qodiqa.selectorLabels" -}}
app.kubernetes.io/name: {{ include "qodiqa.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: gateway
{{- end -}}

{{- define "qodiqa.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "qodiqa.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "qodiqa.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{- define "qodiqa.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-dev-secrets" (include "qodiqa.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "qodiqa.isProd" -}}
{{- if eq .Values.profile "production" -}}true{{- end -}}
{{- end -}}

{{/* A secretKeyRef env entry. Usage: include "qodiqa.secretEnv" (dict "name" "X" "key" "k" "ctx" $ "optional" true) */}}
{{- define "qodiqa.secretEnv" -}}
- name: {{ .name }}
  valueFrom:
    secretKeyRef:
      name: {{ include "qodiqa.secretName" .ctx }}
      key: {{ .key }}
      {{- if .optional }}
      optional: true
      {{- end }}
{{- end -}}

{{/* Fails the render when the production profile is missing what it must have. */}}
{{- define "qodiqa.validate" -}}
{{- if not (has .Values.profile (list "production" "development")) -}}
{{- fail "profile must be 'production' or 'development'" -}}
{{- end -}}
{{- if and .Values.image.tag (not (regexMatch "^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$" (toString .Values.image.tag))) -}}
{{- fail "image.tag is not a valid image tag" -}}
{{- end -}}
{{- if and .Values.image.digest (not (regexMatch "^sha256:[a-f0-9]{64}$" (toString .Values.image.digest))) -}}
{{- fail "image.digest must be sha256:<64 hex>" -}}
{{- end -}}
{{- if eq .Values.profile "production" -}}
{{- if gt (int .Values.replicaCount) 1 -}}
{{- fail "production profile: replicaCount must be 1 (the gateway refuses QODIQA_DEPLOYMENT_MODE=distributed in production: the distributed audit chain has no signed checkpoints or anchors yet); scale up only in the development profile" -}}
{{- end -}}
{{- if not .Values.secrets.existingSecret -}}
{{- fail "production profile: secrets.existingSecret is required (the chart never creates production secrets)" -}}
{{- end -}}
{{- if .Values.secrets.createDevSecret -}}
{{- fail "secrets.createDevSecret is for the development profile only" -}}
{{- end -}}
{{- if not .Values.postgres.ssl -}}
{{- fail "production profile: postgres.ssl must be true" -}}
{{- end -}}
{{- if not .Values.redis.tls -}}
{{- fail "production profile: redis.tls must be true" -}}
{{- end -}}
{{- if and .Values.keystore.useEmptyDir -}}
{{- fail "production profile: keystore.useEmptyDir would lose the signing keys with the pod" -}}
{{- end -}}
{{- if and .Values.gateway.env (hasKey .Values.gateway.env "NODE_ENV") (ne (toString .Values.gateway.env.NODE_ENV) "production") -}}
{{- fail "production profile: gateway.env.NODE_ENV must not override production (the boot rules are the second independent check)" -}}
{{- end -}}
{{- if and .Values.gateway.env (hasKey .Values.gateway.env "PORT") (ne (toString .Values.gateway.env.PORT) (toString .Values.gateway.port)) -}}
{{- fail "production profile: gateway.env.PORT must equal gateway.port (probes and Service target it)" -}}
{{- end -}}
{{- if and .Values.gateway.env (hasKey .Values.gateway.env "QODIQA_OPS_MFA_REQUIRED") (eq (lower (toString .Values.gateway.env.QODIQA_OPS_MFA_REQUIRED)) "false") -}}
{{- fail "production profile: gateway.env.QODIQA_OPS_MFA_REQUIRED must not be false" -}}
{{- end -}}
{{- if and .Values.migrations.enabled (has .Values.migrations.user (list "qodiqa_app" "qodiqa_retention" "qodiqa_system" "qodiqa_reporting" "qodiqa_control" "qodiqa_backup")) -}}
{{- fail "production profile: migrations.user must not be a runtime role" -}}
{{- end -}}
{{- if and (gt (int .Values.replicaCount) 1) .Values.keystore.persistence.enabled (not .Values.keystore.persistence.existingClaim) (not (has "ReadWriteMany" .Values.keystore.persistence.accessModes)) -}}
{{- fail "more than one replica needs a ReadWriteMany keystore claim" -}}
{{- end -}}
{{- end -}}
{{- if and (eq .Values.profile "development") (not .Values.secrets.existingSecret) (not .Values.secrets.createDevSecret) -}}
{{- fail "development profile: set secrets.createDevSecret=true or secrets.existingSecret" -}}
{{- end -}}
{{- end -}}
