import '@testing-library/jest-dom';
import 'jest-axe/extend-expect';
import { TextEncoder } from 'node:util';

Object.defineProperty(globalThis, 'TextEncoder', {
  configurable: true,
  value: TextEncoder,
});

Object.defineProperty(globalThis, 'fetch', {
  configurable: true,
  writable: true,
  value: jest.fn(),
});

Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => undefined,
    removeListener: () => undefined,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    dispatchEvent: () => false,
  }),
});
