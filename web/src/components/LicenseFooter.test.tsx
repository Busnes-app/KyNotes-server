import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import repoLicense from "../../../LICENSE.txt?raw";
import mitLicenseText from "../mit.txt?raw";
import { LicenseFooter, LicenseWindow } from "./LicenseFooter";

describe("license footer", () => {
  it("ships the repository's LICENSE.txt unchanged", () => {
    expect(mitLicenseText).toBe(repoLicense);
  });

  it("shows the copyright line that opens the About window", () => {
    const html = renderToStaticMarkup(<LicenseFooter signedIn={false} />);
    expect(html).toContain(`© ${new Date().getFullYear()} · MIT License`);
    expect(html).toContain('class="license-link"');
    expect(html).toContain("<dialog");
  });

  it("names the app, the developer and the license, with the version badge only when known", () => {
    const withVersion = renderToStaticMarkup(<LicenseWindow version="0.5.0.2" onClose={() => undefined} />);
    expect(withVersion).toContain("KyNotes");
    expect(withVersion).toContain("v0.5.0.2");
    expect(withVersion).toContain("Developed by Busnes.app");
    expect(withVersion).toContain("Licensed under the MIT License");
    expect(withVersion).toContain("Permission is hereby granted");
    expect(renderToStaticMarkup(<LicenseWindow version="" onClose={() => undefined} />)).not.toContain("license-version-badge");
  });
});
