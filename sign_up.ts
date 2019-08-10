import { ServerRequest } from "https://deno.land/std/http/server.ts";
import { v4 as uuidV4 } from "https://deno.land/std/uuid/mod.ts";
import { saslprep } from "https://denopkg.com/chiefbiiko/saslprep/mod.ts";
import {
  SALTBYTES,
  blake2b
} from "https://denopkg.com/chiefbiiko/blake2b/mod.ts";
import {
  encode,
  decode
} from "https://denopkg.com/chiefbiiko/std-encoding/mod.ts";
import { BLAKE2B_CUSTOM_BYTES, Handler, UserPrivate, valid } from "./common.ts";

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
        encode(saslprep(user.password), "utf8"),
        null,
        null,
        BLAKE2B_CUSTOM_BYTES,
        null,
        salt
      ) as Uint8Array;

      // create the user
      await createUser({ ...user, id: uuidV4(), role, password: hash, salt });
    } catch (err) {
      crashed(err);

      return req.respond({ status: 500 });
    }
  };
}
