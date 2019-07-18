import { Server, serve } from "https://deno.land/std/http/server.ts";
import { auth } from "./mod.ts";

const s: Server = serve("0.0.0.0:4190");

async function main(): Promise<void> {
  for await (const req of s) {
    // check req auth

    req.respond({ body: new TextEncoder().encode("Fraud World\n") });
  }
}

main();
