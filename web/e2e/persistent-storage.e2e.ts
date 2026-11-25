import { expect, test } from "@playwright/test";
import { adminConsole, OWNER, person, signIn } from "./people";

declare global {
  interface Window { persistAsked?: number }
}

test("signing in asks the browser to keep the storage that holds the encryption key", async ({ browser }) => {
  const admin = await person(browser);
  const owner = await person(browser);
  try {
    await adminConsole(admin.page);
    const { page } = owner;
    // Counts the requests; the browser still answers them itself.
    await page.addInitScript(() => {
      const storage = navigator.storage;
      const persist = storage.persist.bind(storage);
      window.persistAsked = 0;
      storage.persist = () => {
        window.persistAsked = (window.persistAsked ?? 0) + 1;
        return persist();
      };
    });
    await signIn(page, OWNER.username, OWNER.password);
    // Asked once the vault keeps the key, unless the browser already keeps this site's storage.
    await expect.poll(() => page.evaluate(async () => (window.persistAsked ?? 0) > 0 || (await navigator.storage.persisted()))).toBe(true);
    expect(owner.unexpected).toEqual([]);
  } finally {
    await admin.page.context().close();
    await owner.page.context().close();
  }
});
