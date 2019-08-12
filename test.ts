import { test, runIfMain } from "https://deno.land/std/testing/mod.ts";
import {
  assert,
  assertEquals,
  assertNotEquals
} from "https://deno.land/std/testing/asserts.ts";

/** Precompiled regex. */
const TOKEN_REGEX: RegExp = /[^\.]+\.[^\.]+\.[^\.]+/;

/** Timeable sleeping pill. */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve: () => void) => setTimeout(resolve, ms));
}

test({
  name: "successful signup",
  async fn(): Promise<void> {
    const response: Response = await fetch("http://localhost:4190/signup", {
      method: "POST",
      body: JSON.stringify({ email: "chief@it.com", password: "fraud419" })
    });

    assertEquals(response.status, 201);
  }
});

test({
  name: "conflicting signup",
  async fn(): Promise<void> {
    let body: string = JSON.stringify({
      email: "noop@it.com",
      password: "secret12"
    });

    let response: Response = await fetch("http://localhost:4190/signup", {
      method: "POST",
      body
    });

    assertEquals(response.status, 201);

    response = await fetch("http://localhost:4190/signup", {
      method: "POST",
      body
    });

    assertEquals(response.status, 409);
  }
});

test({
  name: "failed signup due to malformatted email",
  async fn(): Promise<void> {
    const email: string = "@it.wtf";
    const password: string = "weakweak";

    let response: Response = await fetch("http://localhost:4190/signup", {
      method: "POST",
      body: JSON.stringify({ email, password })
    });

    assertEquals(response.status, 400);
  }
});

test({
  name: "failed signup due to too short password",
  async fn(): Promise<void> {
    const email: string = "me@it.yo";
    const password: string = "short";

    let response: Response = await fetch("http://localhost:4190/signup", {
      method: "POST",
      body: JSON.stringify({ email, password })
    });

    assertEquals(response.status, 400);
  }
});

test({
  name: "successful signin",
  async fn(): Promise<void> {
    const email: string = "u@it.wtf";
    const password: string = "weakweak";

    let response: Response = await fetch("http://localhost:4190/signup", {
      method: "POST",
      body: JSON.stringify({ email, password })
    });

    assertEquals(response.status, 201);

    const auth: string = btoa(`${email}:${password}`);

    response = await fetch("http://localhost:4190/signin", {
      method: "POST",
      headers: new Headers({
        authorization: `basic ${auth}`
      })
    });

    assertEquals(response.status, 200);

    const body: { [key: string]: any } = await response.json();

    assert(TOKEN_REGEX.test(body.accessToken));

    assert(TOKEN_REGEX.test(body.refreshToken));

    assertNotEquals(body.accessToken, body.refreshToken);
  }
});

test({
  name: "failed signin due to wrong password",
  async fn(): Promise<void> {
    const email: string = "u@it.wtf";
    const password: string = "weakweak";

    let response: Response = await fetch("http://localhost:4190/signup", {
      method: "POST",
      body: JSON.stringify({ email, password })
    });

    assertEquals(response.status, 201);

    const auth: string = btoa(`${email}:${password}wrong`);

    response = await fetch("http://localhost:4190/signin", {
      method: "POST",
      headers: new Headers({
        authorization: `basic ${auth}`
      })
    });

    assertEquals(response.status, 401);
  }
});

test({
  name: "failed signin due to unknown email",
  async fn(): Promise<void> {
    const email: string = "u@it.wtf";
    const password: string = "weakweak";

    let response: Response = await fetch("http://localhost:4190/signup", {
      method: "POST",
      body: JSON.stringify({ email, password })
    });

    assertEquals(response.status, 201);

    const auth: string = btoa(`unknown@it.wtf:${password}`);

    response = await fetch("http://localhost:4190/signin", {
      method: "POST",
      headers: new Headers({
        authorization: `basic ${auth}`
      })
    });

    assertEquals(response.status, 404);
  }
});

test({
  name: "failed signin due to invalid auth type",
  async fn(): Promise<void> {
    const email: string = "u@it.wtf";
    const password: string = "weakweak";

    let response: Response = await fetch("http://localhost:4190/signup", {
      method: "POST",
      body: JSON.stringify({ email, password })
    });

    assertEquals(response.status, 201);

    const auth: string = btoa(`${email}:${password}`);

    response = await fetch("http://localhost:4190/signin", {
      method: "POST",
      headers: new Headers({
        authorization: `bearer ${auth}`
      })
    });

    assertEquals(response.status, 400);
  }
});

test({
  name: "successful refresh",
  async fn(): Promise<void> {
    const email: string = "ridder@it.nl";
    const password: string = "ridridrid";

    let response: Response = await fetch("http://localhost:4190/signup", {
      method: "POST",
      body: JSON.stringify({ email, password })
    });

    assertEquals(response.status, 201);

    const auth: string = btoa(`${email}:${password}`);

    response = await fetch("http://localhost:4190/signin", {
      method: "POST",
      headers: new Headers({
        authorization: `basic ${auth}`
      })
    });

    assertEquals(response.status, 200);

    const signInBody: { [key: string]: any } = await response.json();

    assert(TOKEN_REGEX.test(signInBody.accessToken));

    assert(TOKEN_REGEX.test(signInBody.refreshToken));

    assertNotEquals(signInBody.accessToken, signInBody.refreshToken);

    response = await fetch("http://localhost:4190/refresh", {
      method: "POST",
      headers: new Headers({
        authorization: `bearer ${signInBody.refreshToken}`
      })
    });

    assertEquals(response.status, 200);

    const refreshBody: { [key: string]: any } = await response.json();

    assert(TOKEN_REGEX.test(refreshBody.accessToken));

    assert(TOKEN_REGEX.test(refreshBody.refreshToken));

    assertNotEquals(refreshBody.accessToken, refreshBody.refreshToken);

    assertNotEquals(signInBody, refreshBody);
  }
});

test({
  name: "failed refresh due to expired refresh token",
  async fn(): Promise<void> {
    const email: string = "djb@math.uic.edu";
    const password: string = "somemathformula";

    let response: Response = await fetch("http://localhost:4190/signup", {
      method: "POST",
      body: JSON.stringify({ email, password })
    });

    assertEquals(response.status, 201);

    const auth: string = btoa(`${email}:${password}`);

    response = await fetch("http://localhost:4190/signin", {
      method: "POST",
      headers: new Headers({
        authorization: `basic ${auth}`
      })
    });

    assertEquals(response.status, 200);

    const signInBody: { [key: string]: any } = await response.json();

    assert(TOKEN_REGEX.test(signInBody.accessToken));

    assert(TOKEN_REGEX.test(signInBody.refreshToken));

    assertNotEquals(signInBody.accessToken, signInBody.refreshToken);

    // letting the refresh token expire
    await sleep(2000);

    response = await fetch("http://localhost:4190/refresh", {
      method: "POST",
      headers: new Headers({
        authorization: `bearer ${signInBody.refreshToken}`
      })
    });

    assertEquals(response.status, 401);
  }
});

test({
  name: "failed refresh due to passing an access token",
  async fn(): Promise<void> {
    const email: string = "tanja@hyperelliptic.org";
    const password: string = "anothermathformula";

    let response: Response = await fetch("http://localhost:4190/signup", {
      method: "POST",
      body: JSON.stringify({ email, password })
    });

    assertEquals(response.status, 201);

    const auth: string = btoa(`${email}:${password}`);

    response = await fetch("http://localhost:4190/signin", {
      method: "POST",
      headers: new Headers({
        authorization: `basic ${auth}`
      })
    });

    assertEquals(response.status, 200);

    const signInBody: { [key: string]: any } = await response.json();

    assert(TOKEN_REGEX.test(signInBody.accessToken));

    assert(TOKEN_REGEX.test(signInBody.refreshToken));

    assertNotEquals(signInBody.accessToken, signInBody.refreshToken);

    response = await fetch("http://localhost:4190/refresh", {
      method: "POST",
      headers: new Headers({
        authorization: `bearer ${signInBody.accessToken}`
      })
    });

    assertEquals(response.status, 401);
  }
});

test({
  name: "failed refresh due to a fake token signature",
  async fn(): Promise<void> {
    const email: string = "moxie@thoughtcrime.org";
    const password: string = "axolotls";

    let response: Response = await fetch("http://localhost:4190/signup", {
      method: "POST",
      body: JSON.stringify({ email, password })
    });

    assertEquals(response.status, 201);

    const auth: string = btoa(`${email}:${password}`);

    response = await fetch("http://localhost:4190/signin", {
      method: "POST",
      headers: new Headers({
        authorization: `basic ${auth}`
      })
    });

    assertEquals(response.status, 200);

    const signInBody: { [key: string]: any } = await response.json();

    assert(TOKEN_REGEX.test(signInBody.accessToken));

    assert(TOKEN_REGEX.test(signInBody.refreshToken));

    assertNotEquals(signInBody.accessToken, signInBody.refreshToken);

    // mallealing the signature
    signInBody.refreshToken = signInBody.refreshToken.replace(
      /\.[^\.]*$/,
      ".ZGVhZGJlZWZkZWFkYmVlZg=="
    );

    response = await fetch("http://localhost:4190/refresh", {
      method: "POST",
      headers: new Headers({
        authorization: `bearer ${signInBody.refreshToken}`
      })
    });

    assertEquals(response.status, 401);
  }
});

runIfMain(import.meta, { parallel: true });
