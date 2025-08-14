import { parseOverridePQDate, sanitizeName, COMPONENT_NAME_MAX_LENGTH } from '../src/constants';

describe('constants edge cases', () => {
  it('parses date-only override', () => {
    const ts = parseOverridePQDate('2028-02-01');
    expect(typeof ts).toBe('number');
  });
  it('parses full ISO', () => {
    const ts = parseOverridePQDate('2028-02-01T10:11:12Z');
    expect(typeof ts).toBe('number');
  });
  it('rejects invalid', () => {
    const ts = parseOverridePQDate('not-a-date');
    expect(ts).toBeUndefined();
  });
  it('sanitizes empty and over-length names', () => {
    const empty = sanitizeName('');
    expect(empty).toBe('component');
    const long = 'x'.repeat(COMPONENT_NAME_MAX_LENGTH+50);
    const cleaned = sanitizeName(long);
    expect(cleaned.length).toBe(COMPONENT_NAME_MAX_LENGTH);
  });
  it('removes disallowed chars and collapses dashes', () => {
    const cleaned = sanitizeName('@@@Hello   World///..__##');
    expect(/^[A-Za-z0-9._-]+$/.test(cleaned)).toBe(true);
  });
});
