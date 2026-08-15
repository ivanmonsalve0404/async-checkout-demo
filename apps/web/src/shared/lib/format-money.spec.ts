import { formatMoney } from './format-money';

describe('formatMoney', () => {
  it('formats integer cents as COP without floating-point input', () => {
    expect(formatMoney(2_500_000, 'COP')).toMatch(/25[.\s]000/);
  });
});
