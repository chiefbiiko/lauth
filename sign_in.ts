import { ServerRequest } from "https://deno.land/std/http/server.ts";
import { saslprep } from "https://denopkg.com/chiefbiiko/saslprep/mod.ts";
import * as BWT from "https://denopkg.com/chiefbiiko/bwt/mod.ts";
import { blake2b } from "https://denopkg.com/chiefbiiko/blake2b/mod.ts";
import { encode } from "https://denopkg.com/chiefbiiko/std-encoding/mod.ts";
import {
  BLAKE2B_CUSTOM_BYTES,
  Handler,
  ONE_HOUR,
  TWO_HOURS,
  TokenTimeToLiveOptions,
  UserPrivate,
  equal,
  valid
} from "./common.ts";

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
      encode(saslprep(password), "utf8"),
      null,
      null,
      BLAKE2B_CUSTOM_BYTES,
      null,
      user.salt
    ) as Uint8Array;

    // assert correct credentials
    if (!equal(hash, user.password)) {
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
