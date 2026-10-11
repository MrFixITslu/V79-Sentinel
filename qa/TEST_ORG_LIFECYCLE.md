# Sentinel synthetic tenant lifecycle — safety gate

Status on 2026-10-09: **No V79 Hub test organization or accounts have been created.**

User authorization: create an isolated, temporary Sentinel test organization and synthetic non-owner accounts, then delete those exact resources when no longer needed. Do not modify existing organizations, users or app customer records.

## Blocker verified on the deployed Hub

- Owner invitations can be created by a platform operator and revoked only while **pending**.
- Accepting an invitation creates a permanent organization and an owner membership.
- Normal non-owner users are introduced through team invitations, not direct user POST for customer organizations.
- Team members can be deleted by an organization owner. The owner cannot be deleted via that route.
- **No supported operator API was found to delete an accepted organization.**
- App provisioning can create external tenant mappings, requiring separately verified deprovision workflows.

## Mandatory execution order

1. Implement and review a platform-operator-only cleanup capability for Sentinel-created test tenants in Hub staging. A candidate exists at `/home/firelion/V79-Sentinel/hub-cleanup-staging` on the Acer; 178 Hub tests and TypeScript checks passed, but authenticated HTTP integration has NOT been completed and there is NO production deployment.
2. Test tenant removal and linked-account cleanup against a synthetic, disposable datastore. Show that owner organization, shared users, billing, invitations, and externally mapped app tenants are protected by fail-closed logic.
3. Complete backup/release/security review before deploying any operator cleanup endpoint. No release is authorized just by creating this plan.
4. Only after step 3 succeeds, create a unique **Sentinel-QA-*** isolated organization by the supported invite/onboarding path. Record its UUID and exact user UUIDs in an access-controlled manifest. Do not store passwords in the manifest.
5. Add synthetic **non-owner** members through supported invitations and use only test data. Preserve existing users and customer workspaces.
6. Run the approved, limited protected-workflow QA.
7. At completion or cancellation, revoke invites, deprovision external test-only app workspaces using their native management paths, then delete exactly the manifest's users and organization using the reviewed cleanup pathway. Verify absence by the same supported API.
8. Retain only redacted QA results and a deletion audit record; don't leave test accounts active.

## What's available now

- `qa/tenant-cleanup.mjs` is a **pure dry-run safety validator**, not live deletion functionality.
- `scripts/test_tenant_cleanup.mjs` checks no mutation, exact org identity, owner preservation, shared-user blocks, billing blocks, and app mapping blocks.
- `qa/protected-qa-policy.json` keeps 9/9 readiness gates closed by default.
- No automated user creation, login, cleanup, app provisioning or database write action has been started.

## Reason for stopping before creation

An accepted Hub invitation is not reversible through currently supported APIs. Creating it before reliable teardown would violate the user's requirement to delete temporary resources.
