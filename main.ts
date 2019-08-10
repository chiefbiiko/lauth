import { Server, serve } from "https://deno.land/std/http/server.ts";
import {
  createSignUpHandler,
  createSignInHandler,
  createRefreshHandler
} from "./mod.ts";

// TODO: create all the handlers

const s: Server = serve("0.0.0.0:4190");

async function main(): Promise<void> {
  console.log("serving @ 0.0.0.0:4190");

  for await (const req of s) {
    if (req.url.endsWith("signup")) {
      signUp(req);
    } else if (req.url.endsWith("signin")) {
      signIn(req);
    } else if (req.url.endsWith("refresh")) {
      refresh(req);
    } else {
      req.respond({ status: 400 });
    }
  }
}

main();
