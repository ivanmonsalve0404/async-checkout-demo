import { render, screen } from '@testing-library/react';
import { AppErrorBoundary } from './app-error-boundary';

const Broken = (): never => {
  throw new Error('synthetic failure');
};

describe('AppErrorBoundary', () => {
  it('prevents a blank screen without exposing internals', () => {
    jest.spyOn(console, 'error').mockImplementation(() => undefined);
    render(
      <AppErrorBoundary>
        <Broken />
      </AppErrorBoundary>,
    );
    expect(screen.getByRole('alert')).toHaveTextContent('La aplicación no pudo continuar');
    expect(screen.queryByText('synthetic failure')).not.toBeInTheDocument();
  });
});
