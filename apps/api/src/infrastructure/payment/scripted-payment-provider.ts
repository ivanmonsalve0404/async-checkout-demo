import type {
  PaymentProvider,
  ProviderCreateOutcome,
  ProviderError,
  ProviderPaymentCommand,
  ProviderObservation,
  ProviderStatus,
} from '../../application/ports/payment-provider';
import type { Result } from '../../application/result/result';
import { err, ok } from '../../application/result/result';

export type FakePaymentScenario =
  | 'FAKE-PAY-01'
  | 'FAKE-PAY-02'
  | 'FAKE-PAY-03'
  | 'FAKE-PAY-04'
  | 'FAKE-PAY-05'
  | 'FAKE-PAY-06'
  | 'FAKE-PAY-07'
  | 'FAKE-PAY-08'
  | 'FAKE-PAY-09'
  | 'FAKE-PAY-10'
  | 'FAKE-PAY-11'
  | 'FAKE-PAY-12';

interface FakeScript {
  readonly create: ProviderCreateOutcome;
  readonly reads: readonly ProviderStatus[];
}

type StoredPayment = Pick<ProviderPaymentCommand, 'reference' | 'amountInCents' | 'currency'>;

const retainPayment = (command: ProviderPaymentCommand): StoredPayment => ({
  reference: command.reference,
  amountInCents: command.amountInCents,
  currency: command.currency,
});

const acknowledged = (status: 'PENDING' | 'APPROVED' | 'DECLINED'): ProviderCreateOutcome => ({
  kind: 'ACKNOWLEDGED',
  providerId: 'provider-fake-001',
  status,
  reference: 'reference-placeholder',
  amountInCents: 0,
  currency: 'COP',
});

const scripts: Readonly<Record<FakePaymentScenario, FakeScript>> = {
  'FAKE-PAY-01': { create: acknowledged('APPROVED'), reads: ['APPROVED'] },
  'FAKE-PAY-02': { create: acknowledged('DECLINED'), reads: ['DECLINED'] },
  'FAKE-PAY-03': { create: acknowledged('PENDING'), reads: ['PENDING', 'APPROVED'] },
  'FAKE-PAY-04': { create: acknowledged('PENDING'), reads: ['PENDING', 'DECLINED'] },
  'FAKE-PAY-05': { create: { kind: 'PROVEN_NOT_SENT' }, reads: [] },
  'FAKE-PAY-06': { create: { kind: 'OUTCOME_UNKNOWN' }, reads: ['PENDING'] },
  'FAKE-PAY-07': {
    create: { kind: 'PROTOCOL_VIOLATION_AFTER_POSSIBLE_SEND' },
    reads: ['UNKNOWN_EXTERNAL'],
  },
  'FAKE-PAY-08': { create: acknowledged('APPROVED'), reads: ['APPROVED', 'APPROVED'] },
  'FAKE-PAY-09': { create: acknowledged('APPROVED'), reads: ['APPROVED', 'DECLINED'] },
  'FAKE-PAY-10': { create: acknowledged('APPROVED'), reads: ['APPROVED'] },
  'FAKE-PAY-11': { create: { kind: 'DEFINITIVE_REJECTION' }, reads: [] },
  'FAKE-PAY-12': { create: acknowledged('PENDING'), reads: ['UNKNOWN_EXTERNAL'] },
};

export const fakePaymentScenarios = Object.freeze(Object.keys(scripts) as FakePaymentScenario[]);

export class ScriptedPaymentProvider implements PaymentProvider {
  private readIndex = 0;
  private readonly commands = new Map<string, StoredPayment>();

  public constructor(private readonly scenario: FakePaymentScenario) {}

  public getPublicConfiguration(): Result<
    Readonly<{
      mode: 'fake';
      captureVariant: 'FAKE_CONTRACT';
      publicKey: string;
      installments: readonly number[];
    }>,
    ProviderError
  > {
    return ok({
      mode: 'fake',
      captureVariant: 'FAKE_CONTRACT',
      publicKey: 'FAKE_CONTRACT_NO_CARD_DATA',
      installments: [1, 2, 3],
    });
  }

  public createOnce(
    command: ProviderPaymentCommand,
  ): Promise<Result<ProviderCreateOutcome, ProviderError>> {
    const scripted = scripts[this.scenario].create;
    const providerId = 'provider_' + command.reference;
    if (scripted.kind === 'OUTCOME_UNKNOWN') {
      this.commands.set(providerId, retainPayment(command));
      return Promise.resolve(ok(scripted));
    }
    if (scripted.kind !== 'ACKNOWLEDGED') return Promise.resolve(ok(scripted));
    this.commands.set(providerId, retainPayment(command));
    return Promise.resolve(
      ok({
        ...scripted,
        providerId,
        reference: command.reference,
        amountInCents: command.amountInCents,
        currency: command.currency,
      }),
    );
  }
  public getByReference(reference: string): Promise<Result<ProviderObservation, ProviderError>> {
    return this.getById('provider_' + reference);
  }

  public getById(providerId: string): Promise<Result<ProviderObservation, ProviderError>> {
    const command = this.commands.get(providerId);
    const status = scripts[this.scenario].reads[this.readIndex];
    if (command === undefined || status === undefined) {
      return Promise.resolve(err({ code: 'FAKE_SCRIPT_EXHAUSTED' }));
    }
    this.readIndex += 1;
    return Promise.resolve(
      ok({
        providerId,
        reference: command.reference,
        amountInCents: command.amountInCents,
        currency: command.currency,
        status,
      }),
    );
  }

  public verifyAndNormalizeEvent(
    eventName: string,
  ): Result<Readonly<{ eventName: string }>, ProviderError> {
    return eventName.startsWith('fake.') ? ok({ eventName }) : err({ code: 'EVENT_REJECTED' });
  }
}
