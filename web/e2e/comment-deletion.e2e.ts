import { expect, test } from "@playwright/test";
import { adminConsole, OWNER, person, signIn, withDialog, openNotebooks, shoot } from "./people";

test("comment deletion confirms, reports failure and leaves a newly selected page alone", async ({ browser }) => {
 const admin = await person(browser);
 const owner = await person(browser, { viewport: { width: 1280, height: 900 } });
 const { page } = owner;
 try {
  await adminConsole(admin.page);
  await signIn(page, OWNER.username, OWNER.password);
  await openNotebooks(page);
  await withDialog(owner,{ type:"prompt",text:"Notebook name",answer:"Comment deletion" },()=>page.getByRole("button",{name:"＋ New notebook"}).click());
  await expect(page.locator(".note-list")).toHaveAttribute("aria-busy","false");
  const save = () => page.waitForResponse(r=>r.request().method()==="PUT" && /\/api\/v1\/objects\/obj_/.test(r.url()) && r.ok());
  for (const title of ["First comment page","Second comment page"]) {
   const created=save(); await page.getByRole("button",{name:"New page",exact:true}).click(); await created;
   const titled=save(); await page.locator(".title-input").fill(title); await titled;
  }
  const panel=page.locator("details.comments");
  if (await panel.getAttribute("open")===null) await panel.locator("summary").click();
  await page.getByPlaceholder("Add a comment…").fill("Remove only this comment");
  await page.getByRole("button",{name:"Comment",exact:true}).click();
  const comment=page.locator(".comment").filter({hasText:"Remove only this comment"});
  await expect(comment).toBeVisible();
  const receipt = page.getByRole("button", { name: /^Last Committed/ });
  if (await receipt.isVisible()) await receipt.click();
  await comment.evaluate(element => element.scrollIntoView({ block: "center" }));
  await shoot("comments",page,process.env.KYNOTES_BASELINE ? "before" : "after","delete-action",comment);
  if (process.env.KYNOTES_BASELINE) return;
  const clickDelete=async()=>{ await comment.getByRole("button",{name:/Comment options/}).click(); await page.getByRole("button",{name:"Delete comment",exact:true}).click(); };
  const confirm="Delete this comment for everyone? This cannot be undone.";
  await withDialog(owner,{type:"confirm",text:confirm,decline:true},clickDelete);
  await expect(comment).toBeVisible();
  await page.route("**/api/v1/comments/*",r=>r.fulfill({status:500,contentType:"application/json",body:'{"error":{"code":"internal","message":"Unable to delete comment"}}'}));
  await withDialog(owner,{type:"confirm",text:confirm},clickDelete);
  await expect(page.locator(".toast.error").filter({hasText:"Unable to delete comment"})).toBeVisible();
  await expect(comment).toBeVisible();
  await page.unroute("**/api/v1/comments/*");
  // A delayed success must never navigate back or remove a different page's comments.
  let release: (()=>void) | undefined;
  const held=new Promise<void>(resolve=>{release=resolve;});
  let started: (()=>void) | undefined;
  const entered=new Promise<void>(resolve=>{started=resolve;});
  await page.route("**/api/v1/comments/*",async route=>{started?.();await held;await route.continue();});
  const deleted=page.waitForResponse(r=>r.request().method()==="DELETE" && /\/api\/v1\/comments\//.test(r.url()));
  await withDialog(owner,{type:"confirm",text:confirm},clickDelete);
  await entered;
  await page.locator(".note-row").filter({hasText:"First comment page"}).click();
  await expect(page.locator(".title-input")).toHaveValue("First comment page");
  release?.();
  expect((await deleted).status()).toBe(204);
  await expect(page.locator(".title-input")).toHaveValue("First comment page");
  await page.locator(".note-row").filter({hasText:"Second comment page"}).click();
  await expect(page.locator(".comment")).toHaveCount(0);
  expect(owner.unexpected).toEqual([]);
 } finally {await admin.page.context().close();await owner.page.context().close();}
});
