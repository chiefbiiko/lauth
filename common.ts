import { ServerRequest } from "https://deno.land/std/http/server.ts";

/** Precompiled email regex. */
const EMAIL_REGEX: RegExp = /(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])/;

/** Token TTL in ms. */
export const ONE_HOUR: number = 1000 * 60 * 60 * 1;
export const TWO_HOURS: number = 1000 * 60 * 60 * 2;

/** Digest length of a salted password. */
export const BLAKE2B_CUSTOM_BYTES: number = 32;

/** Hopefully a somewhat timing-attack-robust buffer equality check. */
export function equal(a: Uint8Array, b: Uint8Array): boolean {
  let diff: number = a.length === b.length ? 0 : 1;

  for (let i: number = Math.max(a.length, b.length) - 1; i >= 0; --i) {
    diff |= a[i] ^ b[i];
  }

  return diff === 0;
}

/** Validation helpers. */
export const valid = {
  email(candidate: string): boolean {
    return EMAIL_REGEX.test(candidate);
  },
  password(candidate: string): boolean {
    return candidate && candidate.length >= 8;
  }
};

/** Generic handler. */
export interface Handler {
  (request: ServerRequest): Promise<void>;
}

/** Sign up handler options. */
export interface TokenTimeToLiveOptions {
  accessTokenTTL?: number;
  refreshTokenTTL?: number;
}

/** User representation. */
export interface User {
  id: any;
  role: any;
  email: string;
  [key: string]: any;
}

/** User representation including sensitive info. */
export interface UserPrivate extends User {
  password: Uint8Array;
  salt: Uint8Array;
}
