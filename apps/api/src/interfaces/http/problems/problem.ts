import { HttpException } from '@nestjs/common';

export type PublicErrorCode = 'PRODUCT_NOT_FOUND' | 'INTERNAL_ERROR' | 'ENVIRONMENT_MISMATCH';

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
