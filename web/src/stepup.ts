import { APIRequestError, loginParams, stepUp } from "./api";
import { deriveAuthSecret } from "./crypto";

/** Derives the login secret from a typed password, exactly as at login, re-proves it for this session and returns it. */
export async function stepUpWithPassword(username: string, password: string): Promise<string> {
  const { loginSalt, iterations } = await loginParams(username);
  const authSecret = await deriveAuthSecret(password, loginSalt, iterations);
  await stepUp(authSecret);
  return authSecret;
}

/** Asks for the password in a modal and steps up with it; rejects when cancelled. The caller keeps the result in memory only. */
export function stepUpAsking(username: string): Promise<string> {
  const dialog = document.createElement("dialog");
  const form = document.createElement("form");
  const title = document.createElement("h2");
  title.id = "password-step-up";
  title.textContent = "Confirm your password";
  dialog.setAttribute("aria-labelledby", title.id);
  const label = document.createElement("label");
  label.textContent = "Password";
  const input = document.createElement("input");
  input.type = "password";
  input.autocomplete = "current-password";
  input.required = true;
  label.append(input);
  const message = document.createElement("p");
  message.setAttribute("aria-live", "polite");
  const confirm = document.createElement("button");
  confirm.textContent = "Confirm";
  const cancel = document.createElement("button");
  cancel.type = "button";
  cancel.textContent = "Cancel";
  form.append(title, label, message, confirm, cancel);
  dialog.append(form);
  document.body.append(dialog);
  return new Promise<string>((resolve, reject) => {
    const close = () => dialog.remove();
    const stop = () => { close(); reject(new Error("Password confirmation cancelled")); };
    dialog.addEventListener("cancel", (event) => { event.preventDefault(); stop(); });
    cancel.onclick = stop;
    form.onsubmit = (event) => {
      event.preventDefault();
      const typed = input.value;
      input.value = "";
      confirm.disabled = true;
      message.textContent = "";
      stepUpWithPassword(username, typed).then((authSecret) => { close(); resolve(authSecret); }, (error) => {
        confirm.disabled = false;
        message.textContent = error instanceof Error ? error.message : "Password not confirmed";
      });
    };
    dialog.showModal();
  });
}

export function isStepUpRequired(error: unknown): boolean {
  return error instanceof APIRequestError && error.code === "step_up_required";
}
