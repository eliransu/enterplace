# Changelog

Every change to Gantry Enterprise that a customer or operator can see, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [Semantic Versioning](https://semver.org/).
Gantry Enterprise and the open source Gantry share one version number: the image `ghcr.io/ggantry/gantry-enterprise:X.Y.Z`
carries both repositories at vX.Y.Z, and the open source changes are in the gantry repository's CHANGELOG.md. How a
release is made: RELEASING.md.

## [Unreleased]

## [0.1.0] - Unreleased

The first tagged release: the open source gateway plus the commercial features, in one image that serves by default,
and a hosted service with a web app.

### One image

- `ghcr.io/ggantry/gantry-enterprise` for amd64 and arm64, under 50 MB, running as a non-root user. It serves
  `/etc/gantry/gantry.policy.yaml` by default and runs every open source command too (`key new`, `audit verify`,
  `check`), so no separate binary is needed.
- The image carries the Helm chart and the Terraform modules under `/deploy`.

### License

- A signed license key (`GANTRY_LICENSE` or `GANTRY_LICENSE_FILE`), checked offline, unlocks the enterprise features.
  An expired license keeps them on for 30 days, then turns them off; model traffic is never stopped. `/healthz` shows
  the license without its token.

### Members and access

- Members with owner, admin and viewer roles, invites by one-time link and password sign-in, on the gateway's own
  console. Removing a person revokes every key named with their email and ends their session at once.
- In the Gantry app: single sign-on per organization through its own OpenID Connect provider (Okta, Entra ID, Google
  Workspace), two-step sign-in with recovery codes, and SCIM 2.0 provisioning.
- Scoped, expiring admin API tokens for staff, each write recorded with the caller's name.

### Governance

- Policy versions with diffs, a dry run against recorded traffic, and approval by a second admin before a change goes
  live.
- Audit export to a signed webhook, Splunk HEC or Datadog, a backfill of up to 90 days, a pull API for a SIEM that
  cannot receive a POST, retention, legal hold and an NDJSON archive.
- Compliance evidence reports for SOC 2, ISO 27001, the EU AI Act and the NIST AI RMF.
- Workload identity: OIDC token exchange for short-lived keys.
- Provider keys from files, HashiCorp Vault or AWS Secrets Manager, rotated without a restart.

### Hosted service and hybrid nodes

- A control plane and web app: sign up, keys, gateways, audit log, spend by team, person and model, and a back office
  for staff.
- A hosted gateway per organization, and hybrid nodes that pull their configuration, ship an allowlist of audit fields
  and guardrail findings, and keep serving when the control plane is down.
- Watch mode for Claude Team and Enterprise subscriptions: Claude Code's own telemetry, usage by person and model,
  with no prompt, answer or tool content stored.
- A device agent with enrolment tokens, a profile per organization, coverage and drift reporting, and MDM templates.
- A page that gives a coding agent the prompt to connect a project to the gateway.

### Deployment

- Docker Compose with Postgres, written from the Docker guide and tested end to end on every change.
- A Helm chart run as a StatefulSet, each replica with its own audit log, several replicas sharing a Postgres store,
  tested on kind.
- Terraform modules for AWS (ECS, RDS, EFS), Google Cloud (Cloud Run, Cloud SQL, Filestore) and Azure (Container Apps,
  Azure Database for PostgreSQL, Azure Files).

### Security

- Fixes from the cloud security review: a credential per hosted gateway, SCIM and password links limited to people of
  one organization, outbound fetches over HTTPS only with no redirects or private addresses, read-only staff, and rate
  limits on public forms.
