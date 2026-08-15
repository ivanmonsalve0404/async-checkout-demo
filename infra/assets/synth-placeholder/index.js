'use strict';

const json = (statusCode, body) => ({
  statusCode,
  headers: {
    'cache-control': 'no-store',
    'content-type': 'application/json; charset=utf-8',
  },
  body: JSON.stringify(body),
});

export const apiHandler = async (event) => {
  if (event && event.rawPath === '/api/health') {
    return json(200, {
      status: 'ok',
      serviceVersion: 'foundation-synth-only',
      environmentCategory: 'preview',
      ready: true,
    });
  }

  return json(503, {
    type: 'about:blank',
    title: 'Foundation synth placeholder',
    status: 503,
    detail: 'Deployable application code is intentionally absent in stage 4 IaC.',
  });
};

export const workerHandler = async () => ({
  accepted: true,
  mode: 'fake',
  effects: 0,
});
