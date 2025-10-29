// test/cvss.test.js
const { calcBaseScore } = require('../src/cvss');

describe('CVSS Base Score Calculator', () => {
  test('should return 9.8 for a critical remote vulnerability', () => {
    const metrics = {
      AV: 'N', AC: 'L', PR: 'N', UI: 'N',
      S: 'U', C: 'H', I: 'H', A: 'H'
    };
    const result = calcBaseScore(metrics);
    expect(result.base).toBeCloseTo(9.8, 1);
  });

  test('should return 0.0 if there is no impact', () => {
    const metrics = {
      AV: 'N', AC: 'L', PR: 'N', UI: 'N',
      S: 'U', C: 'N', I: 'N', A: 'N'
    };
    const result = calcBaseScore(metrics);
    expect(result.base).toBe(0.0);
  });

  test('should handle changed scope correctly', () => {
    const metrics = {
      AV: 'N', AC: 'L', PR: 'N', UI: 'N',
      S: 'C', C: 'H', I: 'H', A: 'H'
    };
    const result = calcBaseScore(metrics);
    expect(result.base).toBeGreaterThan(9.8);
  });
});