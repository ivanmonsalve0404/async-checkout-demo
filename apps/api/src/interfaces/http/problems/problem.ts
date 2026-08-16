import { HttpException } from '@nestjs/common';

export type PublicErrorCode =
  | 'REQUEST_MALFORMED'
  | 'ORIGIN_FORBIDDEN'
  | 'CHECKOUT_NOT_FOUND_OR_FORBIDDEN'
  | 'PRODUCT_NOT_FOUND'
  | 'FIELD_INVALID'
  | 'OUT_OF_STOCK'
  | 'QUOTE_STALE'
  | 'CHECKOUT_EXPIRED'
  | 'PRECONDITION_FAILED'
  | 'IDEMPOTENCY_CONFLICT'
  | 'PAYMENT_ALREADY_IN_PROGRESS'
  | 'STATE_TRANSITION_CONFLICT'
  | 'RATE_LIMITED'
  | 'WEBHOOK_SIGNATURE_INVALID'
  | 'INTERNAL_ERROR'
  | 'ENVIRONMENT_MISMATCH'
  | 'PROVIDER_AUTH_OR_CONFIG_INVALID';

export interface ProblemDetails {
  readonly type: string;
  readonly title: string;
  readonly status: number;
  readonly detail: string;
  readonly instance: string;
  readonly code: PublicErrorCode;
  readonly correlationId: string;
  readonly retryable: boolean;
}

export const createProblem = (
  code: PublicErrorCode,
  status: number,
  correlationId: string,
  instance: string,
): ProblemDetails => {
  const definitions: Record<
    PublicErrorCode,
    Readonly<{ title: string; detail: string; retryable: boolean }>
  > = {
    PRODUCT_NOT_FOUND: {
      title: 'Producto no encontrado',
      detail: 'El producto solicitado no está disponible.',
      retryable: false,
    },
    REQUEST_MALFORMED: {
      title: 'Solicitud inválida',
      detail: 'No pudimos leer la solicitud.',
      retryable: false,
    },
    ORIGIN_FORBIDDEN: {
      title: 'Origen no permitido',
      detail: 'La solicitud no está permitida.',
      retryable: false,
    },
    CHECKOUT_NOT_FOUND_OR_FORBIDDEN: {
      title: 'Checkout no disponible',
      detail: 'El recurso no está disponible.',
      retryable: false,
    },
    FIELD_INVALID: {
      title: 'Revisa los campos',
      detail: 'Hay campos que requieren tu atención.',
      retryable: false,
    },
    OUT_OF_STOCK: {
      title: 'Producto agotado',
      detail: 'No hay inventario disponible.',
      retryable: false,
    },
    QUOTE_STALE: {
      title: 'La cotización cambió',
      detail: 'Actualiza el resumen antes de continuar.',
      retryable: false,
    },
    CHECKOUT_EXPIRED: {
      title: 'Checkout vencido',
      detail: 'Inicia un checkout nuevo.',
      retryable: false,
    },
    PRECONDITION_FAILED: {
      title: 'Versión desactualizada',
      detail: 'Actualiza el checkout e inténtalo de nuevo.',
      retryable: false,
    },
    IDEMPOTENCY_CONFLICT: {
      title: 'Conflicto de operación',
      detail: 'La clave ya fue usada con otros datos.',
      retryable: false,
    },
    PAYMENT_ALREADY_IN_PROGRESS: {
      title: 'Pago en proceso',
      detail: 'Consulta el pago existente.',
      retryable: false,
    },
    STATE_TRANSITION_CONFLICT: {
      title: 'Estado incompatible',
      detail: 'La operación no es válida en el estado actual.',
      retryable: false,
    },
    RATE_LIMITED: {
      title: 'Demasiadas solicitudes',
      detail: 'Espera un momento antes de intentarlo de nuevo.',
      retryable: true,
    },
    WEBHOOK_SIGNATURE_INVALID: {
      title: 'Evento no autorizado',
      detail: 'El evento no pudo verificarse.',
      retryable: false,
    },
    PROVIDER_AUTH_OR_CONFIG_INVALID: {
      title: 'Servicio no disponible',
      detail: 'El servicio de pagos no está habilitado.',
      retryable: false,
    },
    INTERNAL_ERROR: {
      title: 'Error interno',
      detail: 'No fue posible completar la solicitud de forma segura.',
      retryable: true,
    },
    ENVIRONMENT_MISMATCH: {
      title: 'Servicio no disponible',
      detail: 'El servicio no está listo para recibir tráfico.',
      retryable: true,
    },
  };
  const definition = definitions[code];
  return {
    type: `https://errors.example.invalid/${code.toLowerCase()}`,
    title: definition.title,
    status,
    detail: definition.detail,
    instance,
    code,
    correlationId,
    retryable: definition.retryable,
  };
};

export class ProblemException extends HttpException {
  public constructor(problem: ProblemDetails) {
    super(problem, problem.status);
  }
}
