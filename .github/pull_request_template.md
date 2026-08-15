## Scope

- [ ] The change is limited to the stated requirement and its tests.
- [ ] Real payment calls, sandbox credentials and cloud mutations are absent.
- [ ] Fixtures and screenshots contain only synthetic, non-card data.

## Verification

- [ ] `pnpm verify` passes locally.
- [ ] OpenAPI and generated contracts have no unexplained drift.
- [ ] Frontend and backend coverage remain at or above 85% in all four metrics.
- [ ] `pnpm infra:synth` completes without deployment.
- [ ] Secret and dependency scans pass.

## Risk and handoff

- [ ] Security, data, cost and rollback impact are described.
- [ ] Any exception has an owner, expiry and explicit approval.
