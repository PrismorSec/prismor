# Single Sign-On, Directory Provisioning and Workload Identity

Prismor plugs into the identity infrastructure an organization already runs.
Three surfaces, each independent:

| Surface | Protocol | Who it covers | Plan |
|---|---|---|---|
| Console sign-in | OIDC | People opening the Prismor console | Enterprise |
| Directory provisioning | SCIM 2.0 (Users + Groups) | Who is a member, and who is an admin | Enterprise |
| Workload enrollment | AWS IAM (signed STS request) | Agents running on AWS, no shared token | All plans |

Any identity provider that speaks OIDC and SCIM works. Directories such as
LDAP or Active Directory are federated through the identity provider that
fronts them; Prismor never binds to a directory itself.

## Console sign-in (OIDC)

An org owner or admin registers the identity provider in **Admin → SSO**:

1. Enter the email domain (for example `acme.com`), the OIDC discovery URL,
   the client id and the client secret.
2. Register the redirect URI shown in the form in the identity provider:
   `https://<your console host>/api/auth/sso/callback`.
3. Prove domain ownership. The console issues a DNS TXT record value; add it
   at the domain and click **verify**. Sign-in for that domain routes to the
   identity provider only after verification, so a stranger cannot capture a
   domain they do not own.

Users who sign in through the provider land in the org whose domain matched.
Managing providers requires the `sso` entitlement; sign-in itself is never
gated, so an org that downgrades keeps its existing users' access.

Self-hosted deployments can also configure a provider through environment
variables at deploy time; the self-serve flow above needs no redeploy.

## Directory provisioning (SCIM 2.0)

**Admin → Integrations → Directory provisioning** shows the SCIM base URL and
issues a bearer token (shown once; rotate any time). Point the identity
provider's SCIM connector at the base URL with that token.

Supported:

- `POST /Users`, `GET /Users?filter=userName eq "…"` (also `externalId`),
  `GET/PUT/PATCH/DELETE /Users/{id}`, including `active` false/true.
  Deactivating removes the org membership; the account itself is kept (it may
  belong to other orgs). Reactivating restores membership.
- `POST /Groups`, `GET /Groups?filter=displayName eq "…"`,
  `GET/PUT/PATCH/DELETE /Groups/{id}` with `add` / `remove` / `replace`
  member operations in the shapes common identity providers send.

### Roles from groups

Role is derived from group membership, never edited by hand for provisioned
users. In the SCIM card, list the identity-provider group names whose members
should be org admins under **Admin groups** (comma separated). On every group
push:

- a user in any listed group becomes **ADMIN**;
- every other provisioned user is **MEMBER**;
- **OWNER** is never granted or revoked by SCIM, and the last owner of an org
  cannot be deprovisioned through SCIM. Ownership stays a console action.

Seat limits apply to provisioning exactly as to invitations.

## Workload identity (AWS IAM)

A deployed agent on AWS usually has no developer machine and no safe place
for a shared enrollment token. It can enroll with the IAM role it already
runs as:

1. In **Admin → Integrations → Cloud workload identity**, bind the role:
   `arn:aws:iam::<account>:role/<RoleName>`. An IAM path in the ARN is
   dropped on save, because STS reports assumed roles without it. Copy the
   org id shown there.
2. On the workload:

   ```bash
   prismor enroll --aws --org <orgId>
   # optional: --label task-42 --aws-region eu-west-1 --api-base https://<self-hosted console>
   ```

The runtime signs an `sts:GetCallerIdentity` request with the role's
credentials (found the way the AWS SDKs find them: environment, ECS/EKS
container endpoint, IMDSv2, then `~/.aws/credentials`) and sends only the
**signed request** to the control plane. The control plane replays it to
STS, reads the caller's role, and mints a service identity if that role is
bound to the org. Credentials never leave the workload.

What makes a captured request useless elsewhere:

- the signature covers the control-plane host and the org id, so it cannot be
  replayed against another server or into another org;
- the request expires after five minutes;
- the control plane only ever forwards a fixed `GetCallerIdentity` body to an
  STS hostname.

The result is a service identity, listed and revocable under **Devices** like
any agent key. One identity exists per label; re-enrolling under the same
label replaces it. Containers on EC2 with an IMDS hop limit of one cannot
reach IMDSv2: prefer task or pod roles there.

See [Connecting a Self-Hosted Runtime to the Prismor Platform](connecting-to-the-platform.md)
for what the enrolled runtime sends afterwards.
