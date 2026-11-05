import { expect, test, type Page } from "@playwright/test";
import { adminConsole, OWNER, person, signIn, withDialog, openNotebooks } from "./people";

const objectSave = (page: Page) => page.waitForResponse(r=>r.request().method()==="PUT" && /\/api\/v1\/objects\/obj_/.test(r.url()) && r.ok());
async function cached(page: Page, id: string): Promise<string> {
 return page.evaluate(async id => {
  const db=await new Promise<IDBDatabase>((resolve,reject)=>{const r=indexedDB.open("kynotes-web",7);r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);});
  try {return await new Promise<string>((resolve,reject)=>{const r=db.transaction("notes").objectStore("notes").getAll();r.onsuccess=()=>{const note=r.result.find((n:{id:string})=>n.id===id);resolve(note?Array.from(new Uint8Array(note.payload)).join(","):"");};r.onerror=()=>reject(r.error);});} finally {db.close();}
 },id);
}
for (const mode of ["unsent reload","legacy unsent reload","lost response","post-conflict reload"] as const) {
 test(mode,async({browser})=>{
  const admin=await person(browser);const owner=await person(browser);let page=owner.page;
  try {
   await adminConsole(admin.page);await signIn(page,OWNER.username,OWNER.password);await openNotebooks(page);
   await withDialog(owner,{type:"prompt",text:"Notebook name",answer:`Draft ${mode}`},()=>page.getByRole("button",{name:"＋ New notebook"}).click());
   await expect(page.locator(".note-list")).toHaveAttribute("aria-busy","false");
   const created=objectSave(page);await page.getByRole("button",{name:"New page",exact:true}).click();const first=await created;
   const url=first.url();const id=new URL(url).pathname.split("/").at(-1)!;const hash=await page.evaluate(()=>location.hash);
   if(mode==="lost response") {
    let lost=false;
    await page.route(url,async route=>{if(route.request().method()!=="PUT" || lost) return route.fallback();lost=true;const response=await route.fetch();expect(response.ok()).toBe(true);await route.abort();});
    await page.locator(".title-input").fill("Response lost edit");
    await expect(page.locator(".toast.error")).toContainText("Saved locally");
    const retry=page.waitForResponse(r=>r.request().method()==="PUT" && r.url()===url);
    await page.getByRole("button",{name:"Save",exact:true}).click();
    expect((await retry).status()).toBe(200);
    const conflicts=await page.evaluate(async url=>(await (await fetch(url+"/conflicts")).json()) as unknown,url);
    expect(conflicts).toEqual([]);
   } else {
    if(mode==="post-conflict reload") {
     // Another writer advances the server using an authentic sealed body.
     const body=first.request().postDataBuffer()!;const headers=first.request().headers();
     const advance=await page.request.put(url,{data:body,headers:{...headers,"idempotency-key":"advance-"+id,"x-kynotes-base-version":"1"}});
     expect(advance.status()).toBe(200);
     await page.locator(".title-input").fill("First rejected edit");
     await expect(page.getByRole("button",{name:/Keep the other version/})).toBeVisible();
    }
    const old=await cached(page,id);
    // Keep all late/pagehide saves in flight until the document is destroyed.
    await page.route(url,async route=>{if(route.request().method()==="PUT") await new Promise<void>(()=>{});else await route.fallback();});
    const title=mode==="post-conflict reload"?"Latest post-conflict edit":"Unsent cached edit";
    await page.locator(".title-input").fill(title);
    await expect.poll(()=>cached(page,id)).not.toBe(old);
    const sealed=await cached(page,id);
    const context=page.context();await page.close();page=await context.newPage();
    if(mode==="legacy unsent reload") {
      await page.goto("/healthz");
      await page.evaluate(async id=>{
       const db=await new Promise<IDBDatabase>((resolve,reject)=>{const r=indexedDB.open("kynotes-web",7);r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);});
       try {await new Promise<void>((resolve,reject)=>{const tx=db.transaction(["notes","pending"],"readwrite");const r=tx.objectStore("notes").getAll();r.onsuccess=()=>{for(const row of r.result){if(row.id!==id)continue;delete row.unsent;tx.objectStore("notes").put(row);tx.objectStore("pending").delete([row.owner,row.id]);}};tx.oncomplete=()=>resolve();tx.onerror=()=>reject(tx.error);});}finally{db.close();}
      },id);
    }
    let release: (()=>void) | undefined;
    const held=new Promise<void>(resolve=>{release=resolve;});
    await page.route(url,async route=>{if(route.request().method()==="PUT"){await held;await route.continue();}else await route.fallback();});
    const queued=page.waitForRequest(r=>r.method()==="PUT" && r.url()===url,{timeout:25_000});
    const response=page.waitForResponse(r=>r.request().method()==="PUT" && r.url()===url,{timeout:25_000});
    await page.goto("/"+hash);
    await expect(page.locator(".title-input")).toHaveValue(title);
    await expect(page.locator(".ky-status").filter({hasText:"Saved to server"})).toHaveCount(0);
    // Use the real recovery interval: no clock/age changes. The exact persisted edit is resent.
    const request=await queued;
    expect(Array.from(request.postDataBuffer()!).join(",")).toBe(sealed);
    release?.();
    expect((await response).status()).toBe(mode==="post-conflict reload"?409:200);
    if(mode!=="post-conflict reload") {
      const remote=await page.evaluate(async url=>Array.from(new Uint8Array(await (await fetch(url)).arrayBuffer())).join(","),url);
      expect(remote).toBe(sealed);
      await page.reload();await expect(page.locator(".title-input")).toHaveValue(title);
    } else {
      const copies:unknown=await page.evaluate(async url=>await (await fetch(url+"/conflicts")).json(),url);
      if(!Array.isArray(copies)||copies.length!==2) throw new Error("expected both server-held conflict copies");
      const latest:unknown=copies.at(-1);
      if(typeof latest!=="object" || latest===null || !("id" in latest) || typeof latest.id!=="string") throw new Error("missing conflict ID");
      const kept=await page.evaluate(async id=>Array.from(new Uint8Array(await (await fetch(`/api/v1/conflicts/${id}`)).arrayBuffer())).join(","),latest.id);
      expect(kept).toBe(sealed);
    }
   }
  } finally {await admin.page.context().close();await page.context().close();}
 });
}
