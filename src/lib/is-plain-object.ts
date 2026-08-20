/* eslint-disable jsdoc/require-jsdoc */
export function isPlainObject(obj: unknown): obj is Record<string, unknown> {
  return (
    !!obj &&
    typeof obj === 'object' &&
    (Object.getPrototypeOf(obj) === null ||
      Object.getPrototypeOf(obj) === Object.prototype)
  );
}
