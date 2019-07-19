import { ServerRequest } from "https://deno.land/std/http/server.ts";
import { encode } from "https://denopkg.com/chiefbiiko/std-encoding/mod.ts";
import * as BWT from "https://denopkg.com/chiefbiiko/bwt/mod.ts";

/** Token TTL in ms. */
const oneHour: number = 1000 * 60 * 60 * 1;
const twoHours: number = 1000 * 60 * 60 * 2;

/**
 * Generic authentication function factory.
 * Provides signup, signin, and refresh handlers.
 * This module assumes usernames to be immutable.
 */

/** Hopefully a somewhat timing-attack-robust string equality check. */
function constantTimeEqual(a: string, b: string): boolean {
  const length: number = Math.max(a.length, b.length);

  let diff: number = 0;

  if (a.length !== b.length) {
    diff = 1;
  }

  for (let i: number = length - 1; i >= 0; --i) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return diff === 0;
}

/** superauth  */
export interface SuperAuthOptions {
  accessTokenTTL?: number;
  refreshTokenTTL?: number;
}

/**
 * Creates a general purpose auth endpoint handler that issues access and
 * refresh tokens.
 *
 * For MVP purposes param credentialsMap is just a document map, whereas for
 * serious stuff credentials should come from a db.
 */
export function superauth(
  credentialsMap: Map<string, { password: string; role: string }>,
  ownKeyPair: BWT.KeyPair,
  resourceEndpointsPublicKey: BWT.PeerPublicKey,
  {
    accessTokenTTL = oneHour,
    refreshTokenTTL = twoHours
  }: SuperAuthOptions = {}
): (req: ServerRequest) => void {
  // public key and kid document for the auth endpoint itself
  const ownPublicKeyAndKid: BWT.PeerPublicKey = {
    pk: ownKeyPair.pk,
    kid: ownKeyPair.kid
  };

  // stringify function for generating access tokens
  const stringifyAccessToken: BWT.Stringify = BWT.stringifier(
    ownKeyPair.sk,
    resourceEndpointsPublicKey
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

  // auth endpoint handler
  return function auth(req: ServerRequest): void {
    // prepare parsing the auth header value
    const authHeaderValue: string = req.headers.get("Authorization");
    const firstSpace: number = authHeaderValue.indexOf(" ");
    const authType: string = authHeaderValue
      .substr(0, firstSpace)
      .toLowerCase();

    if (authType === "basic") {
      // parse the basic auth header value
      const [username, password] = atob(
        authHeaderValue.substr(firstSpace + 1)
      ).split(":");

      // fetch expected credentials from db
      const credentials: {
        password: string;
        role: string;
      } = credentialsMap.get(username);

      // assert correct credentials
      if (!constantTimeEqual(password, credentials.password)) {
        return req.respond({ status: 401 });
      }

      // now in ms
      const now: number = Date.now();

      // access token TTL
      const accessTokenExp: number = now + (accessTokenTTL || oneHour);

      // refresh token TTL
      const refreshTokenExp: number = now + (refreshTokenTTL || twoHours);

      // stringify an access token
      const accessToken: string = stringifyAccessToken(
        { typ: "BWTv0", iat: now, exp: accessTokenExp, kid: ownKeyPair.kid },
        { subtype: "access", role: credentials.role, username }
      );

      // stringify a refresh token
      const refreshToken: string = stringifyRefreshToken(
        { typ: "BWTv0", iat: now, exp: refreshTokenExp, kid: ownKeyPair.kid },
        { subtype: "refresh", role: credentials.role, username }
      );

      // issue the tokens
      return req.respond({
        status: 200,
        body: encode(JSON.stringify({ accessToken, refreshToken }), "utf8")
      });
    } else if (authType === "bearer") {
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

      // fetch user role from db
      const { role }: { role: string } = credentialsMap.get(
        contents.payload.username
      );

      // now in ms
      const now: number = Date.now();

      // access token TTL
      const accessTokenExp: number = now + (accessTokenTTL || oneHour);

      // refresh token TTL
      const refreshTokenExp: number = now + (refreshTokenTTL || twoHours);

      // stringify an access token
      const accessToken: string = stringifyAccessToken(
        { typ: "BWTv0", iat: now, exp: accessTokenExp, kid: ownKeyPair.kid },
        {
          subtype: "access",
          username: contents.payload.username,
          role
        }
      );

      // stringify a refresh token
      const refreshToken: string = stringifyRefreshToken(
        { typ: "BWTv0", iat: now, exp: refreshTokenExp, kid: ownKeyPair.kid },
        {
          subtype: "refresh",
          role: contents.payload.role,
          username: contents.payload.username
        }
      );

      // issue the tokens
      return req.respond({
        status: 200,
        body: encode(JSON.stringify({ accessToken, refreshToken }), "utf8")
      });
    } else {
      // invalid request
      return req.respond({ status: 400 });
    }
  };
}
