# AUTH-E6-02 sandbox harness

This runner is intentionally separate from local/CI verification. Its default and `--dry-run`
modes perform zero network calls; `--self-test` exercises policy guards, a direct-child bypass
canary, and mid-run expiry canaries through an injected local transport.

```text
node scripts/stage6/sandbox-authorized/run.mjs
node scripts/stage6/sandbox-authorized/run.mjs --self-test
node scripts/stage6/sandbox-authorized/run.mjs --execute
```

`--execute` is fail-closed unless all of the following are true at the same time:

- the worktree is clean and the authorization file matches `HEAD`;
- the authorization is a regular local JSON file matching `authorization.schema.json`;
- `AUTH-E6-02` is active, approves the exact sandbox host hash, and allows at least eight requests;
- the explicit execution arm, per-request kill switch, fixture approval, and mutation limit of one
  are present;
- the exact HTTPS sandbox origin is selected and redirects are rejected;
- sandbox keys, integrity secret, authorized test-card fields, holder, and customer email are
  present only through environment variables.

The coordinator sends a one-use random capability over a private IPC channel. The candidate rejects
direct `--authorized-child` invocation before reading the authorization path or credentials. After
the handshake, both processes independently validate the authorization file. The candidate then
revalidates the unchanged file, clean same-SHA candidate, real clock, required environment, and kill
switch before and after every request and once more before reporting completion.

The environment names are:

```text
STAGE6_SANDBOX_AUTHORIZATION
STAGE6_SANDBOX_EXECUTION
STAGE6_SANDBOX_KILL_SWITCH
STAGE6_SANDBOX_MUTATION_LIMIT
STAGE6_SANDBOX_FIXTURE_AUTHORIZED
STAGE6_SANDBOX_ORIGIN
STAGE6_SANDBOX_PUBLIC_KEY
STAGE6_SANDBOX_PRIVATE_KEY
STAGE6_SANDBOX_INTEGRITY_SECRET
STAGE6_SANDBOX_CARD_NUMBER
STAGE6_SANDBOX_CARD_EXPIRY
STAGE6_SANDBOX_CARD_CVC
STAGE6_SANDBOX_CARD_HOLDER
STAGE6_SANDBOX_CUSTOMER_EMAIL
```

No credential or test-card value is accepted as a CLI argument or authorization-file field. A
successful authorized execution writes one sanitized, same-SHA external-evidence JSON document to
stdout. It contains only hashes, bounded counters, aliases, enums, and UTC timestamps. Store it in a
restricted temporary location and ingest it through the existing external-evidence channel.

The request plan is fixed at eight: three configuration reads (including the dynamic merchant read
immediately before transaction creation), one client tokenization, one transaction
creation, one status read, one non-mutating error-mapping read, and one reconciliation replay read.
There is at most one tokenization POST and at most one transaction POST. The candidate client adapter,
server provider, and in-memory repository are used directly; production application defaults remain
disabled.

## Proposed package integration (not wired)

The CI-safe command may compile the isolated candidate and then run only zero-network modes:

```json
"test:sandbox:authorized": "tsc -p scripts/stage6/sandbox-authorized/tsconfig.json --noEmit && node scripts/stage6/sandbox-authorized/run.mjs --self-test && node scripts/stage6/sandbox-authorized/run.mjs --dry-run"
```

Keep real execution under a separate, manual-only command that is never referenced by CI or the
normal verification aggregate:

```json
"sandbox:authorized:execute": "node scripts/stage6/sandbox-authorized/run.mjs --execute"
```
