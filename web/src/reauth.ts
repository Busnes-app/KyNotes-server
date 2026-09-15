/** Keep the pending request in memory while the user proves this one action to KySignOn. */
export async function confirmSSOAction(challenge: string, csrf: string): Promise<void> {
  const endpoint = `/api/v1/auth/oidc/step-up/${encodeURIComponent(challenge)}`;
  const opened: { popup: Window | null } = { popup: null };
  let verified = false;
  const controller = new AbortController();
  const dialog = document.createElement("dialog");
  const title = document.createElement("h2");
  title.id = `sso-confirm-${challenge}`;
  title.textContent = "Confirm this action";
  dialog.setAttribute("aria-labelledby", title.id);
  const explanation = document.createElement("p");
  explanation.textContent = "Sign in again with KySignOn to authorize only the action you just requested.";
  const proceed = document.createElement("button");
  proceed.textContent = "Continue to KySignOn";
  const cancel = document.createElement("button");
  cancel.textContent = "Cancel";
  dialog.append(title, explanation, proceed, cancel);
  document.body.append(dialog);
  let cancelled = false;
  try {
    await new Promise<void>((resolve, reject) => {
      const stop = () => { cancelled = true; controller.abort(); reject(new Error("Action confirmation cancelled")); };
      dialog.addEventListener("cancel", event => { event.preventDefault(); stop(); });
      cancel.onclick = stop;
      proceed.onclick = () => {
        opened.popup = window.open("about:blank", "_blank", "popup,width=600,height=750");
        if (!opened.popup) { reject(new Error("Allow the KySignOn sign-in window to confirm this action")); return; }
        opened.popup.opener = null;
        proceed.disabled = true;
        explanation.textContent = "Complete sign-in in the KySignOn window. You can cancel here at any time.";
        resolve();
      };
      dialog.showModal();
    });
    // Keep cancellation effective after the sign-in window has opened.
    cancel.onclick = () => { cancelled = true; controller.abort(); };
    const started = await fetch("/api/v1/auth/oidc/step-up", {
      signal: controller.signal, method: "POST", credentials: "include", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify({ challenge }),
    });
    const value: unknown = await started.json();
    if (!started.ok || typeof value !== "object" || value === null || !("url" in value) || typeof value.url !== "string") throw new Error("Unable to start KySignOn confirmation");
    const url = new URL(value.url);
    if (url.protocol !== "https:" && !(url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname))) throw new Error("Invalid sign-in URL");
    // The window was opened synchronously from the user's click to avoid popup blockers.
    const signInWindow = opened.popup;
    if (!signInWindow || cancelled) throw new Error("Action confirmation cancelled");
    signInWindow.location.href = url.href;
    const expires = Date.now() + 5 * 60_000;
    while (!cancelled && Date.now() < expires) {
      const response = await fetch(endpoint, { signal: controller.signal, credentials: "include", cache: "no-store" });
      const status: unknown = await response.json();
      if (!response.ok) throw new Error("Confirmation expired or the session changed");
      if (typeof status === "object" && status !== null && "verified" in status && status.verified === true) {
        if (cancelled) break;
        verified = true;
        return;
      }
      if (signInWindow.closed) break;
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    throw new Error("Action confirmation cancelled or expired");
  } finally {
    opened.popup?.close();
    dialog.close(); dialog.remove();
    if (!verified) await fetch(endpoint, { method: "DELETE", credentials: "include", headers: { "X-CSRF-Token": csrf } }).catch(() => undefined);
  }
}
