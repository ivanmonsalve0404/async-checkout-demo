import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { axe } from 'jest-axe';
import {
  FakeCardTokenizationAdapter,
  SandboxCardTokenizationAdapter,
  type PaymentTokenizationAdapter,
} from '../services/payment-tokenization';
import { passesLuhn } from '../validation/card-validation';
import { cardInputTtlMs, CardStep } from './card-step';

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
    expect(screen.getByRole('textbox', { name: /Vencimiento/ })).toHaveValue('');
    expect(screen.getByRole('textbox', { name: /Código de seguridad/ })).toHaveValue('');
    expect(screen.getByRole('textbox', { name: /Nombre en la tarjeta/ })).toHaveValue('');
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

  it('explains that an expired method must be captured again', () => {
    render(
      <CardStep
        adapter={new FakeCardTokenizationAdapter(() => 'tok_fake_synthetic123')}
        expired
        onTokenized={jest.fn()}
      />,
    );

    expect(screen.getByRole('alert')).toHaveTextContent('método de pago venció');
  });
  it('clears card data from memory five minutes after capture starts', () => {
    jest.useFakeTimers();
    try {
      render(
        <CardStep
          adapter={new FakeCardTokenizationAdapter(() => 'tok_fake_synthetic123')}
          onTokenized={jest.fn()}
        />,
      );
      const number = screen.getByRole('textbox', { name: /Número de tarjeta/ });
      fireEvent.change(number, { target: { value: '4' } });
      expect(number).toHaveValue('4');

      act(() => jest.advanceTimersByTime(cardInputTtlMs));

      expect(number).toHaveValue('');
      expect(screen.getByRole('alert')).toHaveTextContent('método de pago venció');
    } finally {
      jest.useRealTimers();
    }
  });

  it('drops a token that arrives after the capture is cancelled', async () => {
    let resolveToken: (token: string) => void = () => undefined;
    const adapter: PaymentTokenizationAdapter = {
      mode: 'FAKE',
      tokenize: jest.fn(
        () =>
          new Promise<string>((resolve) => {
            resolveToken = resolve;
          }),
      ),
    };
    const onTokenized = jest.fn();
    const { unmount } = render(<CardStep adapter={adapter} onTokenized={onTokenized} />);

    await fillCard();
    await userEvent.click(screen.getByRole('button', { name: 'Continuar' }));
    expect(screen.getByRole('textbox', { name: /Número de tarjeta/ })).toHaveValue('');
    unmount();
    await act(async () => {
      resolveToken('tok_fake_synthetic123');
      await Promise.resolve();
    });

    expect(onTokenized).not.toHaveBeenCalled();
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
