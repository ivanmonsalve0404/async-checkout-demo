import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { axe } from 'jest-axe';
import {
  FakeCardTokenizationAdapter,
  SandboxCardTokenizationAdapter,
} from '../services/payment-tokenization';
import { passesLuhn } from '../validation/card-validation';
import { CardStep } from './card-step';

const validNumber = (): string => {
  const prefix = '4' + '0'.repeat(14);
  return Array.from({ length: 10 }, (_, value) => prefix + String(value)).find(passesLuhn) ?? '';
};

const fillCard = async (): Promise<void> => {
  await userEvent.type(screen.getByRole('textbox', { name: /Número de tarjeta/ }), validNumber());
  await userEvent.type(screen.getByRole('textbox', { name: /Vencimiento/ }), '1299');
  await userEvent.type(screen.getByRole('textbox', { name: /Código de seguridad/ }), '123');
  await userEvent.type(
    screen.getByRole('textbox', { name: /Nombre en la tarjeta/ }),
    'Persona Sintética',
  );
};

describe('CardStep', () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
  });

  it('validates inline without exposing entered values in storage', async () => {
    const onTokenized = jest.fn();
    render(
      <CardStep
        adapter={new FakeCardTokenizationAdapter(() => 'tok_fake_synthetic123')}
        onTokenized={onTokenized}
      />,
    );
    await userEvent.click(screen.getByRole('button', { name: 'Continuar' }));
    expect(screen.getByRole('alert')).toHaveTextContent('Corrige los campos');
    expect(document.activeElement).toBe(screen.getByRole('alert'));
    expect(onTokenized).not.toHaveBeenCalled();
  });

  it('tokenizes once, returns only the opaque token, and clears all fields', async () => {
    const onTokenized = jest.fn();
    render(
      <CardStep
        adapter={new FakeCardTokenizationAdapter(() => 'tok_fake_synthetic123')}
        onTokenized={onTokenized}
      />,
    );
    await fillCard();
    await userEvent.click(screen.getByRole('button', { name: 'Continuar' }));
    await waitFor(() => expect(onTokenized).toHaveBeenCalledWith('tok_fake_synthetic123'));
    expect(screen.getByRole('textbox', { name: /Número de tarjeta/ })).toHaveValue('');
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it('fails closed for sandbox and removes the entered method', async () => {
    render(<CardStep adapter={new SandboxCardTokenizationAdapter()} onTokenized={jest.fn()} />);
    await fillCard();
    await userEvent.click(screen.getByRole('button', { name: 'Continuar' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('sandbox sigue deshabilitada');
    expect(screen.getByRole('textbox', { name: /Número de tarjeta/ })).toHaveValue('');
  });

  it('has no basic accessibility violations', async () => {
    const { container } = render(
      <CardStep
        adapter={new FakeCardTokenizationAdapter(() => 'tok_fake_synthetic123')}
        onTokenized={jest.fn()}
      />,
    );
    expect(await axe(container)).toHaveNoViolations();
  });
});
