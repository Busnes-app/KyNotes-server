import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { networkLines, networkList, OfficeNetworksView } from "./OfficeNetworks";
import adminConsole from "./AdminConsole.tsx?raw";
import component from "./OfficeNetworks.tsx?raw";

const noop = () => undefined;
const render = (props: Partial<Parameters<typeof OfficeNetworksView>[0]>) =>
  renderToStaticMarkup(<OfficeNetworksView status={null} text="" busy={false} message={null} onText={noop} onSave={noop} {...props} />).replace(/&#x27;/g, "'");

describe("office networks card", () => {
  it("shows one network per line and sends them comma-separated", () => {
    expect(networkLines("203.0.113.0/24,198.51.100.7/32")).toBe("203.0.113.0/24\n198.51.100.7/32");
    expect(networkLines("")).toBe("");
    expect(networkList("203.0.113.0/24\n 198.51.100.7 \n\n2001:db8:1::/48, ")).toBe("203.0.113.0/24,198.51.100.7,2001:db8:1::/48");
  });

  it("warns to list only networks you control, shows the configured list read-only and the count", () => {
    const html = render({ status: { networks: "203.0.113.0/24", environment: "192.0.2.0/24,198.18.0.0/24", exempted: 41 }, text: "203.0.113.0/24" });
    expect(html).toContain("Office networks");
    expect(html).toContain("Networks that skip the per-address limit, one per line");
    expect(html).toMatch(/List only networks you control: everyone behind a listed address loses the limit, so never add guest Wi-Fi, a VPN provider or\s+your reverse proxy/);
    expect(html).toContain("192.0.2.0/24, 198.18.0.0/24");
    expect(html).toContain("41 since the last change or restart");
    expect(html).not.toMatch(/<textarea[^>]*disabled/);
  });

  it("shows the server's refusal verbatim as an alert, and stays disabled until loaded", () => {
    const refusal = '"10.0.0.0/8" is too broad; the widest IPv4 range allowed is /16';
    const html = render({ status: { networks: "", environment: "", exempted: 0 }, text: "10.0.0.0/8", message: { text: refusal, error: true } });
    expect(html).toContain('role="alert"');
    expect(html).toContain(refusal.replace(/"/g, "&quot;"));
    expect(html).not.toContain("Also set by the server configuration");
    expect(render({})).toMatch(/<textarea[^>]*disabled/);
  });

  it("saves through the password step-up and sits in the Server section", () => {
    expect(component).toMatch(/withStepUp\(username, \(\) => saveAdminExemptNetworks\(networkList\(text\)\)\)/);
    expect(adminConsole).toContain("<OfficeNetworks username={username} />");
  });
});
