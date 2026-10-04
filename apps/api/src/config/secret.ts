/**
 * Holds a credential-bearing configuration value, such as the database URL, so that logging,
 * JSON serialization or string interpolation of the configuration never prints it (INV-10).
 * Only the module that needs the value calls reveal().
 */
export class SecretValue {
  readonly #value: string;

  constructor(value: string) {
    this.#value = value;
  }

  reveal(): string {
    return this.#value;
  }

  toString(): string {
    return '[REDACTED]';
  }

  toJSON(): string {
    return '[REDACTED]';
  }

  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return 'SecretValue([REDACTED])';
  }
}
