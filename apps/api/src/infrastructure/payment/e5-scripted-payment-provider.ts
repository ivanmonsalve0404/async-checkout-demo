import type {
  PaymentProvider,
  ProviderCreateOutcome,
  ProviderError,
  ProviderObservation,
  ProviderPaymentCommand,
} from '../../application/ports/payment-provider';
import type { Result } from '../../application/result/result';
import { err, ok } from '../../application/result/result';

export type E5PaymentScenario =
  | 'FAKE-E5-01'
  | 'FAKE-E5-02'
  | 'FAKE-E5-03'
  | 'FAKE-E5-04'
  | 'FAKE-E5-05'
  | 'FAKE-E5-06'
  | 'FAKE-E5-07'
  | 'FAKE-E5-08'
  | 'FAKE-E5-09'
  | 'FAKE-E5-10'
  | 'FAKE-E5-11'
  | 'FAKE-E5-12';

type ScriptStatus = ProviderObservation['status'] | 'READ_ERROR';
interface Script {
  readonly create: 'PENDING' | 'APPROVED' | 'DECLINED' | 'OUTCOME_UNKNOWN' | 'PROTOCOL_VIOLATION';
  readonly reads: readonly ScriptStatus[];
  readonly repeatLast?: boolean;
  readonly divergentCreate?: boolean;
}

type StoredPayment = Pick<ProviderPaymentCommand, 'reference' | 'amountInCents' | 'currency'>;

const retainPayment = (command: ProviderPaymentCommand): StoredPayment => ({
  reference: command.reference,
  amountInCents: command.amountInCents,
  currency: command.currency,
});

const scripts: Readonly<Record<E5PaymentScenario, Script>> = {
  'FAKE-E5-01': { create: 'PENDING', reads: ['APPROVED'] },
  'FAKE-E5-02': { create: 'PENDING', reads: ['DECLINED'] },
  'FAKE-E5-03': { create: 'PENDING', reads: ['ERROR'] },
  'FAKE-E5-04': { create: 'PENDING', reads: ['PENDING'], repeatLast: true },
  'FAKE-E5-05': { create: 'OUTCOME_UNKNOWN', reads: ['APPROVED'] },
  'FAKE-E5-06': { create: 'PENDING', reads: ['READ_ERROR'], repeatLast: true },
  'FAKE-E5-07': { create: 'PROTOCOL_VIOLATION', reads: [] },
  'FAKE-E5-08': { create: 'PENDING', reads: [], divergentCreate: true },
  'FAKE-E5-09': { create: 'APPROVED', reads: ['APPROVED'] },
  'FAKE-E5-10': { create: 'PENDING', reads: ['APPROVED', 'APPROVED'] },
  'FAKE-E5-11': { create: 'PENDING', reads: ['APPROVED', 'PENDING'] },
  'FAKE-E5-12': { create: 'PENDING', reads: ['APPROVED'] },
};

export const e5PaymentScenarios = Object.freeze(Object.keys(scripts) as E5PaymentScenario[]);

export class E5ScriptedPaymentProvider implements PaymentProvider {
  private readonly readIndexes = new Map<string, number>();
  private readonly commands = new Map<string, StoredPayment>();
  private readonly externalTransactions = new Set<string>();
  private readonly verifiedEvents = new Set<string>();
  private readonly availableAt = new Map<string, number>();
  private createCallCount = 0;
  private readCallCount = 0;

  public constructor(
    private readonly scenario: E5PaymentScenario,
    private readonly clock: Readonly<{ now(): number }> = { now: () => Date.now() },
  ) {}

  public get createCalls(): number {
    return this.createCallCount;
  }

  public get verifiedEventCount(): number {
    return this.verifiedEvents.size;
  }
  public get readCalls(): number {
    return this.readCallCount;
  }

  public hasExternalTransaction(reference: string): boolean {
    return this.externalTransactions.has(reference);
  }

  public getPublicConfiguration() {
    return ok({
      mode: 'fake' as const,
      captureVariant: 'FAKE_CONTRACT' as const,
      publicKey: 'FAKE_CONTRACT_NO_CARD_DATA',
      installments: [1, 2, 3] as const,
    });
  }

  public createOnce(
    command: ProviderPaymentCommand,
  ): Promise<Result<ProviderCreateOutcome, ProviderError>> {
    this.createCallCount += 1;
    const script = scripts[this.scenario];
    const providerId = `provider_${command.reference}`;
    if (script.create === 'OUTCOME_UNKNOWN') {
      this.commands.set(providerId, retainPayment(command));
      this.externalTransactions.add(command.reference);
      return Promise.resolve(ok({ kind: 'OUTCOME_UNKNOWN' }));
    }
    if (script.create === 'PROTOCOL_VIOLATION') {
      return Promise.resolve(ok({ kind: 'PROTOCOL_VIOLATION_AFTER_POSSIBLE_SEND' }));
    }
    this.commands.set(providerId, retainPayment(command));
    if (this.scenario === 'FAKE-E5-12') this.availableAt.set(providerId, this.clock.now() + 1000);
    const observation = this.observation(
      providerId,
      command,
      script.create,
      script.divergentCreate,
    );
    return Promise.resolve(ok({ kind: 'ACKNOWLEDGED', ...observation, status: script.create }));
  }
  public getByReference(reference: string): Promise<Result<ProviderObservation, ProviderError>> {
    return this.getById(`provider_${reference}`);
  }

  public getById(providerId: string): Promise<Result<ProviderObservation, ProviderError>> {
    const command = this.commands.get(providerId);
    this.readCallCount += 1;
    const script = scripts[this.scenario];
    const availableAt = this.availableAt.get(providerId);
    if (command !== undefined && availableAt !== undefined && this.clock.now() < availableAt) {
      return Promise.resolve(ok(this.observation(providerId, command, 'PENDING', false)));
    }
    const readIndex = this.readIndexes.get(providerId) ?? 0;
    let status = script.reads[readIndex];
    if (status === undefined && script.repeatLast === true) status = script.reads.at(-1);
    if (command === undefined || status === undefined || status === 'READ_ERROR') {
      return Promise.resolve(err({ code: 'FAKE_SCRIPT_EXHAUSTED' }));
    }
    this.readIndexes.set(providerId, readIndex + 1);
    return Promise.resolve(ok(this.observation(providerId, command, status, false)));
  }

  public verifyAndNormalizeEvent(
    eventName: string,
  ): Result<Readonly<{ eventName: string }>, ProviderError> {
    if (!eventName.startsWith('fake.')) return err({ code: 'EVENT_REJECTED' });
    this.verifiedEvents.add(eventName);
    return ok({ eventName });
  }

  private observation(
    providerId: string,
    command: StoredPayment,
    status: ProviderObservation['status'],
    divergent = false,
  ): ProviderObservation {
    return {
      providerId,
      reference: divergent ? `${command.reference}_divergent` : command.reference,
      amountInCents: divergent ? command.amountInCents + 1 : command.amountInCents,
      currency: divergent ? 'USD' : command.currency,
      status,
    };
  }
}
