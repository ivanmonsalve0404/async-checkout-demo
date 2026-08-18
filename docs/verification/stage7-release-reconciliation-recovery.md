# Stage 7 release reconciliation recovery

This workflow is the protected recovery path for a release run that was fully cancelled or
terminated after it opened the durable release-reconciliation journal. It does not rerun the
release attempt. It can only reconstruct an already-written terminal receipt or converge the
same candidate `N` forward and then finalize the missing terminal.

## Fixed boundary

- Workflow: `.github/workflows/stage7-release-reconciliation-recovery.yml`
- Trigger: `workflow_dispatch` only, from `refs/heads/master`
- Protected environment: `assessment-release-reconciliation-recovery`
- Global mutex: `stage7-assessment-release`, with cancellation disabled
- Source identity: original `release.yml` run, attempt `1`, completed as `failure`, `cancelled`,
  or `timed_out`; the selected rollback-check or rollback-resilience job must have the same
  terminal conclusion
- Temporal limit: the protected request and actor must be created no later than the cleanup
  expiry sealed by the original Stage 7 configuration
- Allowed result: `TERMINAL_RESUMED` or `FORWARD_CONVERGED` to the original candidate `N`
- Forbidden operations: rollback to `N-1`, release fence, publication, tag movement, or journal
  deletion before exact preservation

The original release remains blocked while its journal is open. A fence or finalization marker,
a foreign reconciliation journal, a malformed parameter, a mismatched source run/job, or IAM
drift blocks recovery before mutation.

## Two-layer recovery role authority

The source run freezes a pre-deploy base envelope for the dedicated recovery role. This envelope
does not depend on future Lambda versions, S3 versions, or a CloudFront distribution ID.

The role has exactly one inline policy named `stage7-release-reconciliation-recovery`, no attached
policies, and an identical permissions boundary. Its trust policy permits only GitHub OIDC with
audience `sts.amazonaws.com` and subject
`repo:ivanmonsalve0404/async-checkout-demo:environment:assessment-release-reconciliation-recovery`.
The role is distinct from read, deploy, rollback, cleanup, baseline, and journal-cleanup roles.

The base envelope permits only the maximum account/region/release resource prefixes required for
candidate re-promotion, immutable writes below a release-reconciliation journal root, read-only
completion guards, and IAM self-audit. It permits no `DeleteParameter`, rollback to the previous
release, fence write, or publication write.

Before deployment, while the `stage7-aws-auth` job is using its read role, capture the base:

```text
node scripts/stage7/release-reconciliation-recovery-cli.mjs capture-base-role-authority \
  --config "${STAGE7_CONFIG}" \
  --output .stage7/aws-auth/stage7-release-reconciliation-recovery-role-effective-permissions.json \
  --role-audit-output .stage7/aws-auth/stage7-release-reconciliation-recovery-role-audit.json
```

Required environment variables are `AWS_REGION`, `AWS_DEFAULT_REGION`, `STAGE7_AWS_ACCOUNT_ID`,
`STAGE7_RELEASE_RECONCILIATION_RECOVERY_ROLE_ARN`,
`STAGE7_RELEASE_RECONCILIATION_RECOVERY_PERMISSIONS_BOUNDARY_ARN`, and
`STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN`.

The `aws-auth.json` document binds the base authority with these six fields:

1. `reconciliationRecoveryRoleArn`
2. `reconciliationRecoveryPermissionsBoundaryArn`
3. `reconciliationRecoveryRoleEffectivePermissionsRawSha256`
4. `reconciliationRecoveryRoleEffectivePermissionsCanonicalSha256`
5. `reconciliationRecoveryRoleEffectivePermissionsSha256`
6. `reconciliationRecoveryRoleEffectivePolicyProjectionSha256`

The recovery request reopens those exact bytes, rebuilds the original 23-binding intent, derives
an exact session policy from the candidate record and previous manifest, and proves every session
action, resource, and condition is a subset of the frozen base. Every live IAM capture compares
the base authority; STS receives only the narrower approved session policy.

## Causal workflow

The preparation job observes the original run and its paginated jobs through GitHub REST, rebuilds
the intent from source artifacts, and emits a request that binds the original identity, the frozen
base authority, and the dynamic-session subset proof. A protected reviewer must approve the exact
request digest.

After approval, the workflow:

1. assumes the dedicated recovery role with the exact dynamic session policy;
2. recaptures the live base role and boundary and requires equality with the source snapshot;
3. scans the candidate-global fence, finalization, and rollback journal before mutation;
4. resumes an existing terminal without rollback or `PutParameter`, or converges candidate `N`;
5. captures drift and actor-bound `POST_REPROMOTION_VERSIONED` smoke under the read role;
6. re-assumes and re-audits the recovery role before sealing proof chunks and the terminal;
7. snapshots every raw owner, intent, terminal, proof index/chunk, and valid orphan parameter;
8. uploads, re-downloads by artifact ID, verifies the raw ZIP digest and exact entry bytes;
9. assumes the separate journal-cleanup role, recaptures it live, deletes only the preserved exact
   names, and proves residual count zero.

The shared rollback adapter must export `executeVersionedRollbackRecovery`. It receives both
`recoveryActor` and the complete `recoveryIntent`, validates all 23 original bindings, and accepts
only `REPROMOTE_CANDIDATE`. Recovery smoke must accept
`--reconciliation-recovery-actor`; the raw smoke evidence must preserve
`reconciliationRecoveryActorSha256` before terminal finalization.

## Artifacts

All artifacts are attempt-suffixed, scanned through an exact allowlist, include hidden files, and
have 30-day retention:

- `stage7-release-reconciliation-recovery-request-<run>-<attempt>`
- `stage7-release-reconciliation-recovery-preservation-<run>-<attempt>`
- `stage7-release-reconciliation-recovery-closure-<run>-<attempt>`

The preservation ZIP contains exactly the original intent, terminal receipt, recovery outcome,
raw SSM snapshot, live recovery-role authority, and preservation index. The closure records the
separate cleanup-role authority, the exact deleted name set, and residual count zero.

## Productive readiness

The workflow remains fail-closed until the source `stage7-aws-auth` producer emits the base-role
authority and all six bindings, the dedicated role and boundary match the frozen base, and the two
shared adapters described above are present. Tests and validators use simulated AWS responses only;
they never contact AWS.
