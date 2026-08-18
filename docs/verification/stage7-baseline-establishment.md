# Stage 7 closed baseline establishment

This run creates the first real N-1 recovery baseline without publishing a public release. It is
separate from the normal release workflow and must remain fail-closed.

## One-time protected-environment setup

Create these GitHub environments and keep their reviewers separate:

- `assessment-release`: read-only AWS preflight and CDK diff through the configured read role.
- `assessment-release-baseline`: explicit human approval and the dedicated baseline role.
- `assessment-release-recovery`: disable-only recovery through the rollback role. Do not add the
  baseline role to this environment.

Configure the repository variables referenced by `.github/workflows/baseline.yml`:

- `STAGE7_AWS_ACCOUNT_ID` and `STAGE7_AWS_REGION`.
- `STAGE7_AWS_READ_ROLE_ARN`, `STAGE7_AWS_BASELINE_ROLE_ARN`, and
  `STAGE7_AWS_ROLLBACK_ROLE_ARN`.
- `STAGE7_BASELINE_CONFIG_B64`: base64 of the reviewed closed-baseline configuration. The
  configuration itself contains only references and hashes, never secret values.

Configure these environment secrets:

- `STAGE7_ALERT_EMAIL` in `assessment-release-baseline`; its SHA-256 must equal the approved
  destination hash in the configuration.
- `STAGE7_BASELINE_SIGNED_COOKIE_B64` and `STAGE7_BASELINE_EXPIRED_SIGNED_COOKIE_B64` in
  `assessment-release-baseline`. They are used only for the eight-request restricted smoke and are
  deleted before any artifact is uploaded.

The origin token stays in AWS Secrets Manager. Record its ARN and immutable VersionId in the
approved configuration; never copy the token into GitHub.

## Values to collect before dispatch

From the successful Stage 6 run collect:

1. The run ID.
2. The `verification-reports` artifact ID.
3. Its GitHub REST digest in `sha256:<64 lowercase hex>` form.
4. The raw SHA-256 of `output/evidence/stage-6/verification-manifest.json`.

From the candidate checkout collect the exact 40-character commit SHA. The commit must be the
current `master`, the working tree must be clean, and the Stage 6 manifest must name the same commit
and tree. Compute the raw SHA-256 of the exact decoded baseline configuration file. Choose an
internal version such as `v0.0.0-rc.1` and a release ID matching
`rel-YYYYMMDD-HHMM-<first seven candidate characters>`.

## Dispatch and human review

Open **Actions > Stage 7 Closed Baseline Establishment > Run workflow** on `master`. Enter every
exact value above and select `confirm_closed_baseline`.

The workflow then stops at two distinct controls:

1. `assessment-release` reads AWS prerequisites and produces the sanitized IAM evidence and exact
   CDK diff. It cannot create the four release stacks.
2. `assessment-release-baseline` requires a reviewer to inspect that diff and use the exact
   `STAGE7_IAM_DIFF_REVIEWED_SHA256=<digest>` attestation shown in the job summary.

Reject the run if the account, region, domains, certificates, hosted zone, secret VersionId,
bootstrap roles, budget/SNS subscription, stack prefix, or diff differs from the approved config.
Never use bypass approval.

## Expected execution and recovery

After approval, the workflow may create or resume only the exact four-stack prefix. Publication is
`DISABLED` by default. It seeds the synthetic catalog twice, briefly enables only signed-cookie web
access plus the origin-gated API, performs exactly eight probes, and disables access again. The
scheduler remains disabled throughout.

An independent `ensure-disabled` job always runs with the rollback role. It reasserts and verifies
disabled API mapping, CloudFront distribution, and scheduler state even if the establishment job is
cancelled or times out. The final `stage7-previous-release` artifact is created only afterward by
`closeout`; a failed recovery produces no final N-1 artifact.

The successful closeout summary provides:

- baseline run ID;
- final artifact ID and GitHub digest;
- canonical bundle SHA-256.

Provide those four values to the normal `Stage 7 Release` workflow. It downloads and validates the
bundle and its GitHub provenance directly. Do not create `STAGE7_PREVIOUS_*_B64` variables and do
not reconstruct the manifest or compatibility evidence manually.

## What this run never authorizes

The closed baseline run never creates a Git tag or GitHub release, never changes README publication
state, never emits `GATE-E7-03: PASS`, never enables public traffic, and never deletes stacks or
state. A successful baseline artifact is only the immutable N-1 input for a later protected
`FULL_RELEASE_VERSIONED_UPDATE`.
