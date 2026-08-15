import { render, screen } from '@testing-library/react';
import { AppProviders } from './app-providers';

describe('AppProviders', () => {
  it('provides routing and Redux context to its children', () => {
    render(
      <AppProviders>
        <p>Aplicación lista</p>
      </AppProviders>,
    );

    expect(screen.getByText('Aplicación lista')).toBeInTheDocument();
  });
});
