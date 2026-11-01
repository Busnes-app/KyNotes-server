import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { initMenuButton } from "../ky-ui/menu";
import { SETTINGS_TABS, settingsHash } from "../pages";
import { AppFrame, SettingsMenu } from "./AppNav";

// The workspace's items, as main.tsx builds them: every Settings tab, the open one current.
const workspaceItems = (open?: string) => SETTINGS_TABS.map(([id, label]) => ({ href: settingsHash(id), label, current: id === open }));
const items = (html: string) => [...html.matchAll(/<a role="menuitem" tabindex="-1" href="([^"]+)"( aria-current="page")?>([^<]+)<\/a>/g)].map((m) => `${m[3].replace("&amp;", "&")}${m[2] ? "*" : ""} ${m[1]}`);

describe("Settings menu markup", () => {
  it("is a closed menu button over every workspace tab, in tab order", () => {
    const html = renderToStaticMarkup(<SettingsMenu id="m" items={workspaceItems()} current={false} />);
    expect(html).toMatch(/^<div class="ky-menu"><button type="button" class="ky-icon-button" aria-label="Settings" title="Settings" aria-haspopup="menu" aria-expanded="false" aria-controls="m">/);
    expect(html).toContain('<div class="ky-menu-list" id="m" role="menu" aria-label="Settings" hidden="">');
    expect(items(html)).toEqual([
      "Account #/settings/account", "Phones & apps #/settings/devices", "Appearance #/settings/appearance",
      "Reminders #/settings/reminders", "Colleague keys #/settings/colleague-keys", "Unsent edits #/settings/unsent",
    ]);
    expect(html).not.toContain('aria-current');
  });

  it("marks the open tab and the gear current while Settings is open", () => {
    const html = renderToStaticMarkup(<SettingsMenu id="m" items={workspaceItems("reminders")} current />);
    expect(html).toContain('aria-controls="m" aria-current="page"');
    expect(items(html).filter((item) => item.includes("*"))).toEqual(["Reminders* #/settings/reminders"]);
  });

  it("gives the footer and the phone header a menu each, under their own ids", () => {
    const html = renderToStaticMarkup(
      <AppFrame label="Primary" nav={null} user={{ name: "owner", role: "Everyday account" }} settings={{ items: workspaceItems(), current: false }} onSignOut={() => undefined}>page</AppFrame>,
    );
    expect([...html.matchAll(/role="menu" aria-label="Settings"/g)]).toHaveLength(2);
    expect([...html.matchAll(/ id="(settings-menu-[a-z]+)" role="menu"/g)].map((m) => m[1])).toEqual(["settings-menu-header", "settings-menu-footer"]);
  });

  it("offers an administrator only the console's Account and Appearance (Appearance alone under single sign-on)", async () => {
    vi.stubGlobal("location", { hash: "#appearance" });
    vi.stubGlobal("matchMedia", () => ({ matches: false, addEventListener() {}, removeEventListener() {} }));
    vi.stubGlobal("localStorage", { getItem: () => null, setItem() {}, removeItem() {} });
    const { AdminConsole } = await import("./AdminConsole");
    const menu = (sso: boolean) => {
      const html = renderToStaticMarkup(<AdminConsole username="admin" sso={sso} onLogout={() => undefined} password={null} />);
      return items(html.slice(html.indexOf('id="settings-menu-footer"')));
    };
    expect(menu(false)).toEqual(["Account #account", "Appearance* #appearance"]);
    expect(menu(true)).toEqual(["Appearance* #appearance"]);
  });
});

afterEach(() => vi.unstubAllGlobals());

// ky-ui's menu.js on the smallest stand-in DOM it needs: elements that record their listeners.
function fakeMenu(labels: string[]) {
  let active: Fake | null = null;
  type Fake = { attrs: Record<string, string>; hidden: boolean; tabIndex: number; textContent: string; listeners: Record<string, Array<(e: object) => void>>; [k: string]: unknown };
  const el = (attrs: Record<string, string> = {}, textContent = ""): Fake => {
    const self: Fake = {
      attrs, hidden: false, tabIndex: 0, textContent, listeners: {},
      get ownerDocument() { return doc; },
      getAttribute: (name: string) => self.attrs[name] ?? null,
      setAttribute: (name: string, value: string) => { self.attrs[name] = value; },
      addEventListener: (type: string, fn: (e: object) => void) => { (self.listeners[type] ??= []).push(fn); },
      removeEventListener: (type: string, fn: (e: object) => void) => { self.listeners[type] = (self.listeners[type] ?? []).filter((f) => f !== fn); },
      focus: () => { active = self; },
      click: () => fire(self, "click"),
      closest: (selector: string) => (selector === '[role="menuitem"]' && self.attrs.role === "menuitem" ? self : null),
      contains: (other: unknown) => other === self || (self === menu && list.includes(other as Fake)),
    };
    return self;
  };
  const doc = el();
  const list = labels.map((label) => el({ role: "menuitem" }, label));
  const menu = el({ role: "menu" });
  menu.querySelectorAll = () => list;
  doc.getElementById = (id: string) => (id === "m" ? menu : null);
  const button = el({ "aria-controls": "m" });
  // Events reach the element, then (for items) the menu, then the document, as bubbling would.
  function fire(target: Fake, type: string, init: object = {}) {
    let prevented = false;
    const event = { type, target, preventDefault: () => { prevented = true; }, ctrlKey: false, metaKey: false, altKey: false, ...init };
    for (const at of [target, ...(list.includes(target) ? [menu] : []), doc]) for (const fn of at.listeners[type] ?? []) fn(event);
    return prevented;
  }
  return { button, menu, list, doc, fire, focused: () => active?.textContent || (active === button ? "gear" : null) };
}

describe("ky-ui menu.js behind the gear", () => {
  const LABELS = ["Account", "Phones & apps", "Appearance"];

  it("starts closed, with every item out of the tab order", () => {
    const { button, menu, list } = fakeMenu(LABELS);
    initMenuButton(button as unknown as HTMLElement);
    expect(button.attrs["aria-expanded"]).toBe("false");
    expect(menu.hidden).toBe(true);
    expect(list.map((item) => item.tabIndex)).toEqual([-1, -1, -1]);
  });

  it("opens on a click or Enter at the first item, and ArrowUp at the last", () => {
    const { button, menu, fire, focused } = fakeMenu(LABELS);
    initMenuButton(button as unknown as HTMLElement);
    fire(button, "click");
    expect([button.attrs["aria-expanded"], menu.hidden, focused()]).toEqual(["true", false, "Account"]);
    fire(button, "click");
    expect([button.attrs["aria-expanded"], menu.hidden]).toEqual(["false", true]);
    fire(button, "keydown", { key: "ArrowUp" });
    expect([menu.hidden, focused()]).toEqual([false, "Appearance"]);
  });

  it("moves with the arrows (wrapping), Home and End, and closes on Escape back to the gear", () => {
    const { button, menu, list, fire, focused } = fakeMenu(LABELS);
    initMenuButton(button as unknown as HTMLElement);
    fire(button, "keydown", { key: "ArrowDown" });
    expect(focused()).toBe("Account");
    fire(list[0], "keydown", { key: "ArrowUp" });
    expect(focused()).toBe("Appearance");
    fire(list[2], "keydown", { key: "ArrowDown" });
    expect(focused()).toBe("Account");
    fire(list[0], "keydown", { key: "End" });
    expect(focused()).toBe("Appearance");
    fire(list[2], "keydown", { key: "Home" });
    expect(focused()).toBe("Account");
    fire(list[0], "keydown", { key: "Escape" });
    expect([menu.hidden, button.attrs["aria-expanded"], focused()]).toEqual([true, "false", "gear"]);
  });

  it("closes on Tab, on a click outside, and on choosing an item (focus back on the gear)", () => {
    const { button, menu, list, doc, fire, focused } = fakeMenu(LABELS);
    initMenuButton(button as unknown as HTMLElement);
    fire(button, "click");
    fire(list[0], "keydown", { key: "Tab" });
    expect(menu.hidden).toBe(true);
    fire(button, "click");
    fire(doc, "pointerdown");
    expect(menu.hidden).toBe(true);
    fire(button, "click");
    fire(list[1], "click");
    expect([menu.hidden, focused()]).toEqual([true, "gear"]);
  });
});
