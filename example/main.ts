import { Server, serve } from "https://deno.land/std/http/server.ts";
import * as BWT from "https://denopkg.com/chiefbiiko/bwt/mod.ts";
import {
  DynamoDBClient,
  createClient
} from "https://denopkg.com/chiefbiiko/dynamodb/mod.ts";
import { Handler, UserPrivate } from "./../common.ts";
import {
  createSignUpHandler,
  createSignInHandler,
  createRefreshHandler
} from "./../mod.ts";

const INDEX_HTML: Uint8Array = Deno.readFileSync("./index.html");

const ENV: { [key: string]: any } = Deno.env();

const ddbc: DynamoDBClient = createClient({
  accessKeyId: ENV.ACCESS_KEY_ID || "fraud",
  secretAccessKey: ENV.SECRET_ACCESS_KEY || "fraud",
  region: "local"
});

const authEndpointsKeypair: BWT.KeyPair = BWT.generateKeys();

const resourceEndpointsKeypair: BWT.KeyPair = BWT.generateKeys();

const resourceEndpointsPeerPublicKey: BWT.PeerPublicKey = {
  pk: resourceEndpointsKeypair.pk,
  kid: resourceEndpointsKeypair.kid
};

async function emailExists(email: string): Promise<boolean> {
  const result: { [key: string]: any } = await ddbc.getItem({
    TableName: "users_emails",
    Key: { email }
  });

  return !!result.Item;
}

async function createUser(user: UserPrivate): Promise<void> {
  await ddbc.putItem({ TableName: "users", Item: user });

  await ddbc.putItem({
    TableName: "users_emails",
    Item: { email: user.email, id: user.id }
  });
}

async function readUser(id: any): Promise<UserPrivate> {
  const result: { [key: string]: any } = await ddbc.getItem({
    TableName: "users",
    Key: { id }
  });

  return result.Item;
}

const signUp: Handler = createSignUpHandler(
  "CUSTOMER",
  emailExists,
  createUser
);

const signIn: Handler = createSignInHandler(
  authEndpointsKeypair,
  resourceEndpointsPeerPublicKey,
  readUser
);

const refresh: Handler = createRefreshHandler(
  authEndpointsKeypair,
  resourceEndpointsPeerPublicKey,
  readUser
);

const s: Server = serve("localhost:4190");

async function main(): Promise<void> {
  try {
    Deno.run({ args: ["./start_db.sh"] })
  } catch (_) {
    Deno.run({
      args: [
        "java",
        '-D"java.library.path=dynamodb_local_latest/DynamoDBLocal_lib"',
        "-jar",
        '"dynamodb_local_latest/DynamoDBLocal.jar"',
        "-sharedDb"
      ]
    });
  }

  Deno.run({args: ["deno", "--allow-env", "--allow-net", "./setup_db.ts"]});

  console.log("serving @ localhost:4190");

  for await (const req of s) {
    if (req.url.endsWith("signup")) {
      signUp(req);
    } else if (req.url.endsWith("signin")) {
      signIn(req);
    } else if (req.url.endsWith("refresh")) {
      refresh(req);
    } else {
      req.respond({
        status: 200,
        body: INDEX_HTML,
        headers: new Headers({ "content-type": "text/html" })
      });
    }
  }
}

main();
