import { expect, test } from "@playwright/test";
import { adminConsole, createUser, openSettings, person, signIn, signInAndChoose, vaultOf, withDialog, openNotebooks } from "./people";
import { base64, deriveLoginKeys } from "../src/crypto";
import { generateIdentity, wrapIdentity } from "../src/teamKeys";

// Seed a genuine legacy password copy through the normal identity-create boundary.
// This fixture exists solely to exercise the one-time upgrade, not a production writer.
test("legacy identity upgrades without losing its read key, and retries a lost response", async ({ browser }) => {
  const admin = await person(browser), user = await person(browser);
  const username = "pqc-upgrade-user", password = "pqc own horse battery staple", temporary = "temporary pqc horse battery staple";
  const legacy = generateIdentity();
  try {
    await adminConsole(admin.page);await createUser(admin,username,temporary);
    await user.page.route("**/api/v1/me/identity",async(route)=>{
      if (route.request().method() !== "PUT") {await route.continue();return;}
      const params = await (await user.page.request.post("/api/v1/auth/login-params",{data:{username}})).json();
      const session = await (await user.page.request.get("/api/v1/auth/session")).json();
      const keys = await deriveLoginKeys(password,params.loginSalt,params.iterations);
      await route.continue({postData:JSON.stringify({publicKey:base64(legacy.publicKey),wrapAlg:"aes-256-gcm",wrappedPrivateKey:base64(wrapIdentity(keys.userKEK,legacy.privateKey,session.user.id))})});
    });
    await signInAndChoose(user.page,username,temporary,password);
    await expect.poll(async()=> (await user.page.request.get("/api/v1/me/identity")).status()).toBe(200);
    await user.page.unroute("**/api/v1/me/identity");
    await user.page.context().clearCookies();await signIn(user.page,username,password);
    await expect.poll(async()=> (await vaultOf(user.page))?.identity?.privateKey.length).toBe(32);
    const before=(await vaultOf(user.page))!.identity!;
    await openSettings(user.page);
    const card=user.page.locator(".config-card").filter({has:user.page.getByRole("heading",{name:"Upgrade encryption",exact:true})});
    await card.getByLabel("Your password").fill(password);await card.getByRole("button",{name:"Upgrade encryption…"}).click();
    const code=(await card.locator(".recovery-code").textContent())!;
    await card.getByRole("button",{name:"I saved it",exact:true}).click();
    const groupLabel=card.locator("label").filter({hasText:/group [1-7]/});
    const label=(await groupLabel.textContent())!, group=Number(/group ([1-7])/.exec(label)![1]);
    await groupLabel.locator("input").fill(code.split("-")[group-1]);
    let dropped=false;const submissions:string[]=[];
    await user.page.route("**/api/v1/me/identity/pq-upgrade",async(route)=>{
      submissions.push(route.request().postData()!);
      if (!dropped) {dropped=true;expect((await route.fetch()).status()).toBe(200);await route.abort("connectionreset");} else await route.continue();
    });
    await card.getByRole("button",{name:"Save recovery code",exact:true}).click();
    await expect(card.getByRole("status")).toBeVisible();
    await card.getByRole("button",{name:"Save recovery code",exact:true}).click();
    await expect(card).toHaveCount(0);
    expect(submissions).toHaveLength(2);expect(submissions[0]).toBe(submissions[1]);
    const after=(await vaultOf(user.page))!.identity!;
    expect(after.deviceId).toBe(before.deviceId);expect(after.privateKey).toHaveLength(3378);
    expect(after.privateKey.slice(1,33)).toEqual(before.privateKey);
    await openNotebooks(user.page);
    await withDialog(user,{type:"prompt",text:"Notebook name",answer:"After PQ upgrade"},()=>user.page.getByRole("button",{name:"＋ New notebook"}).click());
    await expect(user.page.locator(".workspace-title")).toHaveText("After PQ upgrade");
  } finally {await user.page.context().close();await admin.page.context().close();}
});
