import { test, runIfMain } from "https://deno.land/std/testing/mod.ts";

import { assertEquals } from "https://deno.land/std/testing/asserts.ts";

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

async function readUserById(id: any): Promise<UserPrivate> {
  const result: { [key: string]: any } = await ddbc.getItem({
    TableName: "users",
    Key: { id }
  });

  return result.Item || null;
}

async function readUserByEmail(email: string): Promise<UserPrivate> {
  let result: { [key: string]: any } = await ddbc.getItem({
    TableName: "users_emails",
    Key: { email }
  });

  if (!result.Item) {
    return null;
  }

  result = await ddbc.getItem({
    TableName: "users",
    Key: { id: result.Item.id }
  });

  return result.Item || null;
}

const signUp: Handler = createSignUpHandler(
  "CUSTOMER",
  emailExists,
  createUser
);

const signIn: Handler = createSignInHandler(
  authEndpointsKeypair,
  resourceEndpointsPeerPublicKey,
  readUserByEmail
);

const refresh: Handler = createRefreshHandler(
  authEndpointsKeypair,
  resourceEndpointsPeerPublicKey,
  readUserById
);

async function main(): Promise<void> {
  const s: Server = serve("localhost:4190");

  for await (const req of s) {
    if (req.url.endsWith("signup")) {
      signUp(req);
    } else if (req.url.endsWith("signin")) {
      signIn(req);
    } else if (req.url.endsWith("refresh")) {
      refresh(req);
    } else {
      req.respond({ status: 404 });
    }
  }
}

main();

test({
  name: "successful signup",
  async fn(): Promise<void> {
    const body: string = JSON.stringify({
      email: "chief@it.com",
      password: "fraud"
    });

    const response: Response = await fetch("http://localhost:4190/signup", {
      method: "POST",
      body
    });

    assertEquals(response.status, 201);
  }
});

runIfMain(import.meta);
