import { formatMoney, formatMoneyForAssistiveTechnology } from './format-money';

describe('formatMoney', () => {
  it('formats integer cents as COP without floating-point input', () => {
    expect(formatMoney(2_500_000, 'COP')).toMatch(/25[.\s]000/);
  });

  it('names Colombian pesos explicitly for assistive technology', () => {
    expect(formatMoneyForAssistiveTechnology(2_500_000, 'COP')).toMatch(
      /25[.\s]000 pesos colombianos/i,
    );
  });
});
