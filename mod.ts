/**
 * Generic BWT token authentication.
 * Provides signup, signin, and refresh handlers.
 * This module assumes user ids and email adresses to be immutable and unique.
 */

import { ServerRequest } from "https://deno.land/std/http/server.ts";
import {
  SALTBYTES,
  blake2b
} from "https://denopkg.com/chiefbiiko/blake2b/mod.ts";
import {
  encode,
  decode
} from "https://denopkg.com/chiefbiiko/std-encoding/mod.ts";
import * as BWT from "https://denopkg.com/chiefbiiko/bwt/mod.ts";
import { v4 as uuidV4 } from "https://deno.land/std/uuid/mod.ts";

/** Token TTL in ms. */
const ONE_HOUR: number = 1000 * 60 * 60 * 1;
const TWO_HOURS: number = 1000 * 60 * 60 * 2;

/** Digest length of a salted password. */
const BLAKE2B_CUSTOM_BYTES: number = 32;

/** Hopefully a somewhat timing-attack-robust buffer equality check. */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  let diff: number = a.length === b.length ? 0 : 1;

  for (let i: number = Math.max(a.length, b.length) - 1; i >= 0; --i) {
    diff |= a[i] ^ b[i];
  }

  return diff === 0;
}

/** Validation helpers. */
const valid = {
  email(candidate: string): boolean {
    // TODO
    return false;
  },
  password(candidate: string): boolean {
    // TODO
    return false;
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

/** Creates a generic signup handler */
export function createSignUpHandler(
  role: any,
  emailExists: (email: string) => Promise<boolean>,
  createUser: (user: UserPrivate) => Promise<void>,
  crashed: (err: Error) => void = console.error
): Handler {
  return async function signUp(req: ServerRequest): Promise<void> {
    try {
      // all parsing & input validation will be done with a schema
      const user: any = JSON.parse(decode(await req.body(), "utf8"));

      if (!user || !valid.email(user.email) || !valid.password(user.password)) {
        return req.respond({ status: 400 });
      }

      // enforce email uniqueness in our nosql storage
      if (await emailExists(user.email)) {
        return req.respond({ status: 409 });
      }

      // gen a salt for that user
      const salt: Uint8Array = crypto.getRandomValues(
        new Uint8Array(SALTBYTES)
      );

      // hash it so fictive storage takeover would not expose plain passwords
      const hash: Uint8Array = blake2b(
        encode(user.password, "utf8"),
        null,
        null,
        BLAKE2B_CUSTOM_BYTES,
        null,
        salt
      );

      // create the user
      await createUser({ ...user, id: uuidV4(), role, password: hash, salt });
    } catch (err) {
      crashed(err);

      return req.respond({ status: 500 });
    }
  };
}

/** Creates a generic signin handler. */
export function createSignInHandler(
  ownKeyPair: BWT.KeyPair,
  resourceEndpointsPeerPublicKey: BWT.PeerPublicKey,
  readUser: (email: string) => Promise<UserPrivate>,
  {
    accessTokenTTL = ONE_HOUR,
    refreshTokenTTL = TWO_HOURS
  }: TokenTimeToLiveOptions = {}
): Handler {
  // public key and kid document for the auth endpoint itself
  const ownPublicKeyAndKid: BWT.PeerPublicKey = {
    pk: ownKeyPair.pk,
    kid: ownKeyPair.kid
  };

  // stringify function for generating access tokens
  const stringifyAccessToken: BWT.Stringify = BWT.stringifier(
    ownKeyPair.sk,
    resourceEndpointsPeerPublicKey
  );

  // stringify function for generating refresh tokens
  const stringifyRefreshToken: BWT.Stringify = BWT.stringifier(
    ownKeyPair.sk,
    ownPublicKeyAndKid
  );

  return async function signIn(req: ServerRequest): Promise<void> {
    // prepare parsing the auth header value
    const authHeaderValue: string = req.headers.get("Authorization");

    const firstSpace: number = authHeaderValue.indexOf(" ");

    const authType: string = authHeaderValue
      .substr(0, firstSpace)
      .toLowerCase();

    // assert correct auth mech
    if (authType !== "basic") {
      return req.respond({ status: 400 });
    }

    // parse the basic auth header value
    const [email, password] = atob(
      authHeaderValue.substr(firstSpace + 1)
    ).split(":");

    // validate the incoming credentials
    if (!valid.email(email) || !valid.password(password)) {
      return req.respond({ status: 400 });
    }

    // fetch expected credentials from db
    const user: UserPrivate = await readUser(email);

    // hash the incoming password to a comparable salted hash
    const hash: Uint8Array = blake2b(
      encode(password, "utf8"),
      null,
      null,
      BLAKE2B_CUSTOM_BYTES,
      null,
      user.salt
    );

    // assert correct credentials
    if (!constantTimeEqual(hash, user.password)) {
      return req.respond({ status: 401 });
    }

    // issuing an access and refresh token
    const now: number = Date.now();

    const accessToken: string = stringifyAccessToken(
      {
        typ: "BWTv0",
        iat: now,
        exp: now + accessTokenTTL,
        kid: ownKeyPair.kid
      },
      { subtype: "access", id: user.id, role: user.role }
    );

    const refreshToken: string = stringifyRefreshToken(
      {
        typ: "BWTv0",
        iat: now,
        exp: now + refreshTokenTTL,
        kid: ownKeyPair.kid
      },
      { subtype: "refresh", id: user.id, role: user.role }
    );

    return req.respond({
      status: 200,
      body: encode(JSON.stringify({ accessToken, refreshToken }), "utf8")
    });
  };
}

/** Creates a generic refresh handler. */
export function createRefreshHandler(
  ownKeyPair: BWT.KeyPair,
  resourceEndpointsPeerPublicKey: BWT.PeerPublicKey,
  readUser: (id: any) => Promise<UserPrivate>,
  {
    accessTokenTTL = ONE_HOUR,
    refreshTokenTTL = TWO_HOURS
  }: TokenTimeToLiveOptions = {}
): Handler {
  // public key and kid document for the auth endpoint itself
  const ownPublicKeyAndKid: BWT.PeerPublicKey = {
    pk: ownKeyPair.pk,
    kid: ownKeyPair.kid
  };

  // stringify function for generating access tokens
  const stringifyAccessToken: BWT.Stringify = BWT.stringifier(
    ownKeyPair.sk,
    resourceEndpointsPeerPublicKey
  );

  // stringify function for generating refresh tokens
  const stringifyRefreshToken: BWT.Stringify = BWT.stringifier(
    ownKeyPair.sk,
    ownPublicKeyAndKid
  );

  // parse function for verifying refresh tokens
  const parseRefreshToken: BWT.Parse = BWT.parser(
    ownKeyPair.sk,
    ownPublicKeyAndKid
  );

  return async function refresh(req: ServerRequest): Promise<void> {
    // prepare parsing the auth header value
    const authHeaderValue: string = req.headers.get("Authorization");

    const firstSpace: number = authHeaderValue.indexOf(" ");

    const authType: string = authHeaderValue
      .substr(0, firstSpace)
      .toLowerCase();

    // assert correct auth mech
    if (authType !== "bearer") {
      return req.respond({ status: 400 });
    }

    // parse the refresh token from the bearer auth header value
    const token: string = authHeaderValue.substr(firstSpace + 1);

    // verify the token
    const contents: BWT.Contents = parseRefreshToken(token);

    // assert we got a valid refresh token
    if (!contents) {
      return req.respond({ status: 401 });
    }

    // make sure the token is a refresh token
    if (contents.payload.subtype !== "refresh") {
      return req.respond({ status: 403 });
    }

    // issuing an access and refresh token
    const user: UserPrivate = await readUser(contents.payload.id);

    const now: number = Date.now();

    const accessToken: string = stringifyAccessToken(
      {
        typ: "BWTv0",
        iat: now,
        exp: now + accessTokenTTL,
        kid: ownKeyPair.kid
      },
      { subtype: "access", id: contents.payload.id, role: user.role }
    );

    const refreshToken: string = stringifyRefreshToken(
      {
        typ: "BWTv0",
        iat: now,
        exp: now + refreshTokenTTL,
        kid: ownKeyPair.kid
      },
      { subtype: "refresh", id: contents.payload.id, role: user.role }
    );

    return req.respond({
      status: 200,
      body: encode(JSON.stringify({ accessToken, refreshToken }), "utf8")
    });
  };
}
