import type { Request } from 'express';

export type RequestWithCorrelation = Request & Readonly<{ correlationId: string }>;
