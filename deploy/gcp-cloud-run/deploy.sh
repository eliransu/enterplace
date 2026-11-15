#!/usr/bin/env bash
# Gantry on Cloud Run with Cloud SQL for PostgreSQL, from the published image, in one command:
#   OPENAI_API_KEY=sk-... bash <(curl -fsSL https://raw.githubusercontent.com/eliransu/gantry/main/deploy/gcp-cloud-run/deploy.sh)
# Runs in Cloud Shell or anywhere gcloud is signed in. Safe to run again: what exists is kept.
# Settings, all optional: GOOGLE_CLOUD_PROJECT, GOOGLE_CLOUD_REGION (us-central1), GANTRY_SERVICE (gantry),
# GANTRY_IMAGE (ghcr.io/eliransu/gantry:latest), GANTRY_DB_TIER (db-f1-micro), and the provider keys
# OPENAI_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY (each one set is kept in Secret Manager).
# The Run on Google Cloud button runs this as its postcreate hook (app.json beside it).
set -euo pipefail

project="${GOOGLE_CLOUD_PROJECT:-$(gcloud config get-value project 2>/dev/null)}"
region="${GOOGLE_CLOUD_REGION:-us-central1}"
service="${GANTRY_SERVICE:-${K_SERVICE:-gantry}}"
image="${GANTRY_IMAGE:-ghcr.io/eliransu/gantry:latest}"
tier="${GANTRY_DB_TIER:-db-f1-micro}"
instance="${service}-db"
if [ -z "$project" ]; then
  echo "No Google Cloud project: run gcloud config set project <id>, or set GOOGLE_CLOUD_PROJECT, then run this again." >&2
  exit 2
fi
gcloud config set project "$project" >/dev/null

echo "Enabling the APIs (Cloud Run, Cloud SQL Admin, Secret Manager)."
gcloud services enable run.googleapis.com sqladmin.googleapis.com secretmanager.googleapis.com

# The secret's latest version, made only when the secret does not exist yet.
secret() {
  local name="$1" value="$2"
  if ! gcloud secrets describe "$name" >/dev/null 2>&1; then
    printf '%s' "$value" | gcloud secrets create "$name" --data-file=- >/dev/null
  fi
}

if ! gcloud sql instances describe "$instance" >/dev/null 2>&1; then
  echo "Creating Cloud SQL instance $instance ($tier, PostgreSQL 16). This takes several minutes."
  gcloud sql instances create "$instance" --database-version=POSTGRES_16 --edition=ENTERPRISE \
    --tier="$tier" --region="$region" --storage-size=10 --storage-auto-increase
fi
gcloud sql databases describe gantry --instance="$instance" >/dev/null 2>&1 \
  || gcloud sql databases create gantry --instance="$instance"
connection="$(gcloud sql instances describe "$instance" --format='value(connectionName)')"
if ! gcloud secrets describe "${service}-database-url" >/dev/null 2>&1; then
  password="$(openssl rand -hex 24)"
  gcloud sql users create gantry --instance="$instance" --password="$password" >/dev/null 2>&1 \
    || gcloud sql users set-password gantry --instance="$instance" --password="$password"
  # The Cloud SQL connector gives the service a Unix socket: Gantry connects to it without TLS of its own.
  secret "${service}-database-url" "host=/cloudsql/${connection} user=gantry password=${password} dbname=gantry"
fi

# The service runs as the Compute Engine default service account unless you change it.
number="$(gcloud projects describe "$project" --format='value(projectNumber)')"
account="${number}-compute@developer.gserviceaccount.com"
gcloud projects add-iam-policy-binding "$project" --member="serviceAccount:${account}" \
  --role=roles/cloudsql.client --condition=None >/dev/null

secrets="DATABASE_URL=${service}-database-url:latest"
for name in OPENAI_API_KEY ANTHROPIC_API_KEY GEMINI_API_KEY; do
  id="${service}-$(echo "$name" | tr '[:upper:]_' '[:lower:]-')"
  if [ -n "${!name:-}" ]; then
    secret "$id" "${!name}"
  fi
  if gcloud secrets describe "$id" >/dev/null 2>&1; then
    secrets="${secrets},${name}=${id}:latest"
  fi
done
for id in $(echo "$secrets" | tr ',' '\n' | cut -d= -f2 | cut -d: -f1); do
  gcloud secrets add-iam-policy-binding "$id" --member="serviceAccount:${account}" \
    --role=roles/secretmanager.secretAccessor >/dev/null
done
# The button sets the keys it asked for on the service itself (K_SERVICE is its hook's), and a deploy keeps them.
if [ -z "${K_SERVICE:-}" ] && [ "$secrets" = "DATABASE_URL=${service}-database-url:latest" ]; then
  echo "No provider key: set OPENAI_API_KEY, ANTHROPIC_API_KEY or GEMINI_API_KEY and run this again." >&2
  exit 2
fi

echo "Deploying $image as Cloud Run service $service."
# One instance with CPU always on: the gateway polls the store between requests and keeps one audit chain.
gcloud run deploy "$service" --image="$image" --region="$region" --port=8080 \
  --cpu=1 --memory=512Mi --min-instances=1 --max-instances=1 --no-cpu-throttling \
  --add-cloudsql-instances="$connection" --set-secrets="$secrets" --allow-unauthenticated

url="$(gcloud run services describe "$service" --region="$region" --format='value(status.url)')"
cat <<DONE

Gantry is up at $url
Console: $url/console
The admin key is printed once in the logs of the first revision that reached the database:
  gcloud logging read 'resource.type="cloud_run_revision" AND resource.labels.service_name="$service" AND textPayload:"GANTRY_KEY="' --limit=1 --format='value(textPayload)'
DONE
