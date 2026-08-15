import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { CheckoutResponse } from '../api/checkout-api';
import {
  CustomerDeliveryStep,
  readCustomerDelivery,
  validateCustomerDelivery,
} from './customer-delivery-step';

const money = { amountInCents: 1_000, currency: 'COP' as const };
const checkout: CheckoutResponse = {
  checkoutId: 'checkout_123456',
  status: 'DRAFT',
  version: 1,
  product: {
    productId: 'product_123456',
    sku: 'SKU_1',
    name: 'Producto',
    description: 'Sintético',
    imageUrl: 'http://localhost/product.svg',
    unitPrice: money,
    available: 1,
  },
  quote: {
    quoteId: 'quote_12345678',
    version: 1,
    productId: 'product_123456',
    quantity: 1,
    subtotal: money,
    baseFee: money,
    deliveryFee: money,
    total: { amountInCents: 3_000, currency: 'COP' },
    expiresAt: '2099-01-01T00:00:00Z',
  },
  expiresAt: '2099-01-01T01:00:00Z',
};

const fill = async (): Promise<void> => {
  await userEvent.type(
    screen.getByRole('textbox', { name: 'Nombre completo' }),
    'Persona Sintética',
  );
  await userEvent.type(
    screen.getByRole('textbox', { name: 'Correo electrónico' }),
    'PERSONA@EXAMPLE.TEST',
  );
  await userEvent.type(screen.getByRole('textbox', { name: 'Teléfono' }), '+57 300 000 0000');
  await userEvent.type(screen.getByRole('textbox', { name: 'Dirección' }), 'Calle sintética 123');
  await userEvent.type(screen.getByRole('textbox', { name: 'Ciudad' }), 'Bogotá');
  await userEvent.type(
    screen.getByRole('textbox', { name: 'Departamento o región' }),
    'Cundinamarca',
  );
};

describe('CustomerDeliveryStep', () => {
  it('reports required fields and returns focus to the summary', async () => {
    render(<CustomerDeliveryStep checkout={checkout} onBack={jest.fn()} onSave={jest.fn()} />);
    await userEvent.click(screen.getByRole('button', { name: 'Continuar' }));
    expect(screen.getByRole('alert')).toHaveTextContent('Corrige');
    expect(document.activeElement).toBe(screen.getByRole('alert'));
  });

  it('normalizes PII and sends only the OpenAPI fields', async () => {
    const onSave = jest.fn().mockResolvedValue(undefined);
    render(<CustomerDeliveryStep checkout={checkout} onBack={jest.fn()} onSave={onSave} />);
    await fill();
    await userEvent.click(screen.getByRole('button', { name: 'Continuar' }));
    await waitFor(() =>
      expect(onSave).toHaveBeenCalledWith(
        {
          fullName: 'Persona Sintética',
          email: 'persona@example.test',
          phone: '+573000000000',
        },
        {
          addressLine1: 'Calle sintética 123',
          city: 'Bogotá',
          region: 'Cundinamarca',
        },
      ),
    );
  });

  it('preserves input after a recoverable network failure and supports back', async () => {
    const onBack = jest.fn();
    render(
      <CustomerDeliveryStep
        checkout={checkout}
        onBack={onBack}
        onSave={jest.fn().mockRejectedValue(new Error('offline'))}
      />,
    );
    await fill();
    await userEvent.click(screen.getByRole('button', { name: 'Continuar' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Conservamos');
    expect(screen.getByRole('textbox', { name: 'Nombre completo' })).toHaveValue(
      'Persona Sintética',
    );
    await userEvent.click(screen.getByRole('button', { name: 'Atrás' }));
    expect(onBack).toHaveBeenCalledTimes(1);
  });

  it('omits empty optional fields and rejects hostile/oversized values', () => {
    const form = document.createElement('form');
    for (const [name, value] of Object.entries({
      fullName: 'Persona',
      email: 'P@EXAMPLE.TEST',
      phone: '300-000-0000',
      addressLine1: 'Calle 123',
      addressLine2: '',
      city: 'Bogotá',
      region: 'Cundinamarca',
      postalCode: '',
      deliveryInstructions: '',
    })) {
      const input = document.createElement('input');
      input.name = name;
      input.value = value;
      form.append(input);
    }
    const values = readCustomerDelivery(form);
    expect(values.delivery).not.toHaveProperty('postalCode');
    expect(
      validateCustomerDelivery(
        { fullName: '<x>', email: 'bad', phone: '1' },
        {
          addressLine1: '<bad>',
          city: '1',
          region: '1',
          postalCode: '**',
        },
      ),
    ).toEqual(
      expect.objectContaining({
        fullName: expect.any(String),
        email: expect.any(String),
        phone: expect.any(String),
        addressLine1: expect.any(String),
        city: expect.any(String),
        region: expect.any(String),
        postalCode: expect.any(String),
      }),
    );
  });
});
