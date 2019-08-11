import { ServerRequest } from "https://deno.land/std/http/server.ts";
import * as BWT from "https://denopkg.com/chiefbiiko/bwt/mod.ts";
import { encode } from "https://denopkg.com/chiefbiiko/std-encoding/mod.ts";
import {
  Handler,
  ONE_HOUR,
  TWO_HOURS,
  TokenTimeToLiveOptions,
  UserPrivate
} from "./common.ts";

/** Creates a generic refresh handler. */
export function createRefreshHandler(
  ownKeyPair: BWT.KeyPair,
  resourceEndpointsPeerPublicKey: BWT.PeerPublicKey,
  readUserById: (id: any) => Promise<UserPrivate>,
  crashed: (err: Error) => void = console.error,
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
    try {
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
      const user: UserPrivate = await readUserById(contents.payload.id);

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
    } catch (err) {
      crashed(err);

      return req.respond({ status: 500 });
    }
  };
}
