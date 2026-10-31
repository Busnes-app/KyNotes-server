import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { appMark } from "../ky-ui/appmarks";
import { AppRail } from "./AppNav";

const apps = [
  { id: "kypost", name: "KyPost", url: "https://mail.example.com/api/auth/oidc/login" },
  { id: "kynotes", name: "KyNotes", url: "https://notes.example.com/api/v1/auth/oidc/login" },
];

describe("app rail", () => {
  it("links each app with its mark, href exactly as given, and marks KyNotes current", () => {
    const html = renderToStaticMarkup(<AppRail apps={apps} />);
    expect(html.startsWith('<nav class="ky-app-rail" aria-label="Apps"><p class="ky-app-rail-label" aria-hidden="true">Apps</p><ul>')).toBe(true);
    const links = [...html.matchAll(/<a ([^>]*)><img ([^>]*)\/><\/a>/g)].map((m) => [m[1], m[2]]);
    expect(links.map(([a]) => a)).toEqual([
      'href="https://mail.example.com/api/auth/oidc/login" title="KyPost" aria-label="KyPost"',
      'href="https://notes.example.com/api/v1/auth/oidc/login" title="KyNotes" aria-label="KyNotes" aria-current="page"',
    ]);
    expect(links[0][1]).toBe(`src="${appMark("kypost")}" width="24" height="24" alt=""`);
  });

  it("leaves the nav out when the list is empty", () => {
    expect(renderToStaticMarkup(<AppRail apps={[]} />)).toBe("");
  });
});
