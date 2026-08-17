import { strict as assert } from 'node:assert';
import { Buffer } from 'node:buffer';
import { TextDecoder } from 'node:util';

const URL = /\b(?:https?|wss?):\/\/[^\s"\\]+/iu;
const EMAIL = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/iu;
const AUTHORIZATION_VALUE = /\b(?:Basic|Bearer)\s+[A-Za-z0-9._~+/=-]{8,}/u;
const PRIVATE_KEY = /-----BEGIN [A-Z ]*PRIVATE KEY-----/u;
const PROVIDER_SECRET = /\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9_-]{8,}/iu;
const JWT = /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/u;
const SENSITIVE_FIELD_VALUE =
  /"(?:api[_-]?key|secret|token|password|private[_-]?key|client[_-]?secret|cookie|email|phone|pan|card(?:Number)?|cvc|cvv|securityCode|expiry|expiration)"\s*:\s*"(?:[^"\\]|\\.)+"/iu;
const RAW_SENSITIVE_FLAG = /"containsSensitiveData"\s*:\s*true\b/u;
const QUOTED_PAN = /"(?:[0-9][ -]?){13,19}"/u;
const QUOTED_PHONE = /"\+?[1-9][0-9 ()-]{7,18}"/u;

const NUMERIC_PAN = /(?<![0-9A-Za-z"])[0-9]{13,19}(?![0-9A-Za-z"])/gu;

const luhnValid = (digits) => {
  let sum = 0;
  let doubleDigit = false;
  for (let index = digits.length - 1; index >= 0; index -= 1) {
    let digit = Number(digits[index]);
    if (doubleDigit && (digit *= 2) > 9) digit -= 9;
    sum += digit;
    doubleDigit = !doubleDigit;
  }
  return sum % 10 === 0;
};
const sourceContainsNumericPan = (sourceText) =>
  [...sourceText.matchAll(NUMERIC_PAN)].some(([digits]) => luhnValid(digits));
export class StrictJsonError extends Error {
  constructor(code) {
    super(code);
    this.name = 'StrictJsonError';
    this.code = code;
  }
}

const reject = (code) => {
  throw new StrictJsonError(code);
};

const decodeUtf8 = (source) => {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(source);
  } catch {
    reject('SOURCE_UTF8_INVALID');
  }
};

export const sourceContainsForbiddenData = (sourceText) =>
  [
    URL,
    EMAIL,
    AUTHORIZATION_VALUE,
    PRIVATE_KEY,
    PROVIDER_SECRET,
    JWT,
    SENSITIVE_FIELD_VALUE,
    RAW_SENSITIVE_FLAG,
    QUOTED_PAN,
    QUOTED_PHONE,
  ].some((pattern) => pattern.test(sourceText)) || sourceContainsNumericPan(sourceText);

const assertNoDuplicateJsonKeys = (sourceText) => {
  let offset = 0;
  const skipWhitespace = () => {
    while (/\s/u.test(sourceText[offset] ?? '')) offset += 1;
  };
  const scanString = () => {
    if (sourceText[offset] !== '"') reject('JSON_INVALID');
    const start = offset;
    offset += 1;
    while (offset < sourceText.length) {
      const character = sourceText[offset];
      if (character === '"') {
        offset += 1;
        try {
          return JSON.parse(sourceText.slice(start, offset));
        } catch {
          reject('JSON_INVALID');
        }
      }
      if (character === '\\') {
        offset += 1;
        if (offset >= sourceText.length) reject('JSON_INVALID');
        if (sourceText[offset] === 'u') {
          const unicodeEscape = sourceText.slice(offset + 1, offset + 5);
          if (!/^[0-9a-f]{4}$/iu.test(unicodeEscape)) reject('JSON_INVALID');
          offset += 5;
          continue;
        }
        if (!/["\\/bfnrt]/u.test(sourceText[offset])) reject('JSON_INVALID');
      } else if (character.codePointAt(0) < 0x20) {
        reject('JSON_INVALID');
      }
      offset += 1;
    }
    reject('JSON_INVALID');
  };
  const scanNumber = () => {
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u.exec(
      sourceText.slice(offset),
    );
    if (match === null) reject('JSON_INVALID');
    offset += match[0].length;
  };
  const scanLiteral = (literal) => {
    if (sourceText.slice(offset, offset + literal.length) !== literal) reject('JSON_INVALID');
    offset += literal.length;
  };
  const scanArray = () => {
    offset += 1;
    skipWhitespace();
    if (sourceText[offset] === ']') {
      offset += 1;
      return;
    }
    while (true) {
      scanValue();
      skipWhitespace();
      if (sourceText[offset] === ']') {
        offset += 1;
        return;
      }
      if (sourceText[offset] !== ',') reject('JSON_INVALID');
      offset += 1;
      skipWhitespace();
    }
  };
  const scanObject = () => {
    offset += 1;
    skipWhitespace();
    const keys = new Set();
    if (sourceText[offset] === '}') {
      offset += 1;
      return;
    }
    while (true) {
      const key = scanString();
      if (keys.has(key)) reject('SOURCE_DUPLICATE_KEY');
      keys.add(key);
      skipWhitespace();
      if (sourceText[offset] !== ':') reject('JSON_INVALID');
      offset += 1;
      scanValue();
      skipWhitespace();
      if (sourceText[offset] === '}') {
        offset += 1;
        return;
      }
      if (sourceText[offset] !== ',') reject('JSON_INVALID');
      offset += 1;
      skipWhitespace();
    }
  };
  function scanValue() {
    skipWhitespace();
    const character = sourceText[offset];
    if (character === '"') scanString();
    else if (character === '{') scanObject();
    else if (character === '[') scanArray();
    else if (character === 't') scanLiteral('true');
    else if (character === 'f') scanLiteral('false');
    else if (character === 'n') scanLiteral('null');
    else scanNumber();
    skipWhitespace();
  }
  scanValue();
  if (offset !== sourceText.length) reject('JSON_INVALID');
};

export const parseStrictJsonSource = (source, { scanForbiddenData = true } = {}) => {
  const sourceText = decodeUtf8(source);
  if (scanForbiddenData && sourceContainsForbiddenData(sourceText)) reject('SOURCE_FORBIDDEN_DATA');
  assertNoDuplicateJsonKeys(sourceText);
  try {
    const parsed = JSON.parse(sourceText);
    if (scanForbiddenData && sourceContainsForbiddenData(JSON.stringify(parsed))) {
      reject('SOURCE_FORBIDDEN_DATA');
    }
    return parsed;
  } catch (error) {
    if (error instanceof StrictJsonError) throw error;
    reject('JSON_INVALID');
  }
};

const schemaReference = (rootSchema, reference) => {
  const match = /^#\/\$defs\/([A-Za-z0-9_-]+)$/u.exec(reference);
  return match === null ? undefined : rootSchema.$defs?.[match[1]];
};

const valueHasType = (value, type) => {
  if (type === 'object')
    return value !== null && typeof value === 'object' && !Array.isArray(value);
  if (type === 'array') return Array.isArray(value);
  if (type === 'string') return typeof value === 'string';
  if (type === 'integer') return Number.isSafeInteger(value);
  if (type === 'number') return typeof value === 'number' && Number.isFinite(value);
  if (type === 'boolean') return typeof value === 'boolean';
  if (type === 'null') return value === null;
  return false;
};

export const validateJsonSchemaSubset = (value, schema, rootSchema = schema) => {
  try {
    if (schema === false) return false;
    if (schema === true) return true;
    if (schema === null || typeof schema !== 'object' || Array.isArray(schema)) return false;
    if (schema.$ref !== undefined) {
      if (typeof schema.$ref !== 'string') return false;
      const referenced = schemaReference(rootSchema, schema.$ref);
      return referenced !== undefined && validateJsonSchemaSubset(value, referenced, rootSchema);
    }
    if (Object.hasOwn(schema, 'const') && !Object.is(value, schema.const)) return false;
    if (schema.enum !== undefined) {
      if (!Array.isArray(schema.enum) || !schema.enum.some((entry) => Object.is(value, entry))) {
        return false;
      }
    }
    if (schema.type !== undefined && !valueHasType(value, schema.type)) return false;
    if (typeof value === 'string' && schema.pattern !== undefined) {
      if (typeof schema.pattern !== 'string' || !new RegExp(schema.pattern, 'u').test(value)) {
        return false;
      }
    }
    if (typeof value === 'number') {
      if (schema.minimum !== undefined && value < schema.minimum) return false;
      if (schema.maximum !== undefined && value > schema.maximum) return false;
    }
    if (Array.isArray(value)) {
      if (schema.minItems !== undefined && value.length < schema.minItems) return false;
      if (schema.maxItems !== undefined && value.length > schema.maxItems) return false;
      const prefixItems = schema.prefixItems ?? [];
      if (!Array.isArray(prefixItems)) return false;
      if (
        !prefixItems.every(
          (itemSchema, index) =>
            index >= value.length || validateJsonSchemaSubset(value[index], itemSchema, rootSchema),
        )
      ) {
        return false;
      }
      if (schema.items === false && value.length > prefixItems.length) return false;
      if (
        schema.items !== undefined &&
        schema.items !== false &&
        !value
          .slice(prefixItems.length)
          .every((entry) => validateJsonSchemaSubset(entry, schema.items, rootSchema))
      ) {
        return false;
      }
    }
    if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      const keys = Object.keys(value);
      if (schema.minProperties !== undefined && keys.length < schema.minProperties) return false;
      if (schema.maxProperties !== undefined && keys.length > schema.maxProperties) return false;
      if (
        schema.required !== undefined &&
        (!Array.isArray(schema.required) ||
          !schema.required.every((key) => Object.hasOwn(value, key)))
      ) {
        return false;
      }
      const properties = schema.properties ?? {};
      if (properties === null || typeof properties !== 'object' || Array.isArray(properties)) {
        return false;
      }
      if (
        schema.additionalProperties === false &&
        keys.some((key) => !Object.hasOwn(properties, key))
      ) {
        return false;
      }
      if (
        !keys.every(
          (key) =>
            !Object.hasOwn(properties, key) ||
            validateJsonSchemaSubset(value[key], properties[key], rootSchema),
        )
      ) {
        return false;
      }
    }
    return true;
  } catch {
    return false;
  }
};

export const selfTestStrictJson = () => {
  assert.deepEqual(parseStrictJsonSource(Buffer.from('{"one":1,"nested":{"two":2}}')), {
    one: 1,
    nested: { two: 2 },
  });
  assert.throws(
    () => parseStrictJsonSource(Buffer.from('{"one":1,"o\\u006ee":2}')),
    (error) => error instanceof StrictJsonError && error.code === 'SOURCE_DUPLICATE_KEY',
  );
  assert.throws(
    () => parseStrictJsonSource(Buffer.from('{"value":"https://owned.invalid","value":"safe"}')),
    (error) => error instanceof StrictJsonError && error.code === 'SOURCE_FORBIDDEN_DATA',
  );
  const providerSecret = ['sk', 'live', '1234567890'].join('_');
  assert.throws(
    () => parseStrictJsonSource(Buffer.from(JSON.stringify({ token: providerSecret }))),
    (error) => error instanceof StrictJsonError && error.code === 'SOURCE_FORBIDDEN_DATA',
  );
  assert.throws(
    () =>
      parseStrictJsonSource(
        Buffer.from('{"containsSensitiveData":true,"containsSensitiveData":false}'),
      ),
    (error) => error instanceof StrictJsonError && error.code === 'SOURCE_FORBIDDEN_DATA',
  );
  assert.throws(
    () => parseStrictJsonSource(Buffer.from('{"to\\u006ben":"sk\\u005flive\\u005f1234567890"}')),
    (error) => error instanceof StrictJsonError && error.code === 'SOURCE_FORBIDDEN_DATA',
  );
  const numericPan = ['4111', '1111', '1111', '1111'].join('');
  assert.throws(
    () => parseStrictJsonSource(Buffer.from(`{"count":${numericPan}}`)),
    (error) => error instanceof StrictJsonError && error.code === 'SOURCE_FORBIDDEN_DATA',
  );

  const schema = {
    type: 'object',
    additionalProperties: false,
    required: ['id', 'checks'],
    properties: {
      id: { const: 'ONE' },
      checks: {
        type: 'array',
        minItems: 1,
        maxItems: 1,
        prefixItems: [{ $ref: '#/$defs/pass' }],
        items: false,
      },
    },
    $defs: {
      pass: {
        type: 'object',
        additionalProperties: false,
        required: ['status'],
        properties: { status: { const: 'PASS' } },
      },
    },
  };
  assert.equal(validateJsonSchemaSubset({ id: 'ONE', checks: [{ status: 'PASS' }] }, schema), true);
  assert.equal(validateJsonSchemaSubset({ id: 'ONE', checks: [] }, schema), false);
  assert.equal(
    validateJsonSchemaSubset({ id: 'ONE', checks: [{ status: 'PASS', extra: true }] }, schema),
    false,
  );
};
