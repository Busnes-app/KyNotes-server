import { APIRequestError, loginParams, stepUp } from "./api";
import { deriveAuthSecret } from "./crypto";
import { loginFloor } from "./loginUpgrade";

/** Derives the login secret from a typed password, exactly as at login, re-proves it for this session and returns it. */
export async function stepUpWithPassword(username: string, password: string): Promise<string> {
  const { loginSalt, iterations } = await loginParams(username);
  const authSecret = await deriveAuthSecret(password, loginSalt, iterations, loginFloor(username));
  await stepUp(authSecret);
  return authSecret;
}

/** Asks for the password in a modal and steps up with it; rejects when cancelled. The caller keeps the result in memory only. */
export function stepUpAsking(username: string): Promise<string> {
  const dialog = document.createElement("dialog");
  dialog.className = "ky-dialog";
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
  cancel.className = "secondary";
  cancel.textContent = "Cancel";
  const actions = document.createElement("div");
  actions.className = "dialog-actions";
  actions.append(cancel, confirm);
  form.append(title, label, message, actions);
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

/** Runs a protected action; when the server wants the password again, asks for it in a dialog and runs the action once more. */
export async function withStepUp<T>(username: string, action: () => Promise<T>, ask: (username: string) => Promise<unknown> = stepUpAsking): Promise<T> {
  try {
    return await action();
  } catch (error) {
    if (!isStepUpRequired(error)) throw error;
    await ask(username);
    return action();
  }
}
