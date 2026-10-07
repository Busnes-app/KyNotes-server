// Fractional order keys: base-36 fractions compared as plain strings. A key never ends
// in "0", so there is always room for another key between two distinct keys.
const DIGITS = "0123456789abcdefghijklmnopqrstuvwxyz";
const KEY = /^[0-9a-z]*[1-9a-z]$/;
export const MAX_ORDER_KEY = 512;

export const isOrderKey = (value: unknown): value is string =>
  typeof value === "string" && value.length <= MAX_ORDER_KEY && KEY.test(value);

/** Returns a key strictly between `before` and `after` (null = open end). */
export function keyBetween(before: string | null, after: string | null): string {
  const a = before ?? "";
  let b = after;
  if (b !== null && a >= b) throw new Error("order keys out of order");
  let out = "";
  for (let i = 0; ; i += 1) {
    const low = i < a.length ? DIGITS.indexOf(a[i]) : 0;
    const high = b === null ? DIGITS.length : DIGITS.indexOf(b[i]);
    if (low === high) { out += DIGITS[low]; continue; }
    // Step one digit at an open end so repeated appends/prepends grow keys slowly.
    const pick = before !== null && after === null ? low + 1
      : before === null && after !== null ? high - 1
      : Math.floor((low + high) / 2);
    if (pick > low && pick < high) {
      const key = out + DIGITS[pick];
      if (key.length > MAX_ORDER_KEY) throw new Error("order key limit reached");
      return key;
    }
    out += DIGITS[low];
    b = null;
  }
}
