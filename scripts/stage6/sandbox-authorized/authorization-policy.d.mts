export const SANDBOX_ORIGIN: 'https://sandbox.wompi.co';
export const SANDBOX_HOST: 'sandbox.wompi.co';
export const EXPECTED_EXTERNAL_REQUESTS: 8;

export interface SandboxAuthorization {
  readonly schemaId: 'async-checkout-stage6-auth02-authorization';
  readonly schemaVersion: 1;
  readonly stage: 6;
  readonly commitSha: string;
  readonly runId: string;
  readonly reviewerAlias: string;
  readonly authorization: {
    readonly id: 'AUTH-E6-02';
    readonly status: 'APPROVED';
    readonly scope: 'AUTHORIZED_PROVIDER_SANDBOX_SMOKE';
    readonly approvalSha256: string;
    readonly approvedTargetSha256: string;
    readonly approvedAtUtc: string;
    readonly expiresAtUtc: string;
    readonly ownerAlias: string;
    readonly maxRequests: number;
  };
  readonly target: {
    readonly classification: 'AUTHORIZED_PROVIDER_SANDBOX';
    readonly environment: 'sandbox';
    readonly hostSha256: string;
    readonly allowlistVerified: true;
    readonly production: false;
  };
  readonly fixture: {
    readonly classification: 'AUTHORIZED_PROVIDER_TEST_CARD';
    readonly cardNumberSha256: string;
    readonly authorized: true;
    readonly rawValueCaptured: false;
  };
  readonly containsSensitiveData: false;
}

export interface SandboxAuthorizationContext {
  readonly authorization: SandboxAuthorization;
  readonly commitSha: string;
  readonly sourcePath: string;
  readonly sourceSha256: string;
  readonly repositoryRoot: string;
  readonly schemaPath: string;
}

export class SandboxAuthorizationError extends Error {
  public readonly code: string;
}

export function loadAuthorizationContext(input: {
  readonly repositoryRoot: string;
  readonly schemaPath: string;
  readonly sourcePath: string | undefined;
  readonly now?: Date;
  readonly expectedCommitSha?: string;
}): SandboxAuthorizationContext;

export function revalidateAuthorizationContext(
  context: SandboxAuthorizationContext,
  now?: Date,
): SandboxAuthorizationContext;

export function validateRequiredEnvironment(
  environment: NodeJS.ProcessEnv | Readonly<Record<string, string | undefined>>,
  authorization: SandboxAuthorization,
): void;

export function sha256(value: string | NodeJS.ArrayBufferView): string;
export function selfTestAuthorizationPolicy(schemaPath: string): void;
