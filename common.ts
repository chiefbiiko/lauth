import { ServerRequest } from "https://deno.land/std/http/server.ts";

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
    // TODO
    return true;
  },
  password(candidate: string): boolean {
    // TODO
    return true;
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
