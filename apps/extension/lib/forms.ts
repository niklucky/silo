/**
 * Finding and filling login forms. Deliberately plain heuristics: a visible
 * password field, the text field right before it, and the username-first step
 * of two-page sign-ins. Sign-up and change-password forms get no logins, only
 * a generated password.
 */

export interface LoginFields {
  username: HTMLInputElement | null;
  password: HTMLInputElement | null;
}

const TEXT_TYPES = new Set(["text", "email", "tel"]);
const USERNAME_HINT = /user|login|e-?mail|account|identifier|phone/i;

/** The login form `field` belongs to, or null when it is not part of one. */
export function loginFieldsFor(field: HTMLInputElement): LoginFields | null {
  if (!usable(field)) return null;
  const inputs = inputsAround(field);
  const passwords = inputs.filter(isPassword);
  // Two or more password fields: sign-up ("repeat password") or change password.
  if (passwords.length > 1) return null;
  const [password = null] = passwords;

  if (field.type === "password") {
    if (field !== password) return null;
    return { username: usernameBefore(inputs, field), password: field };
  }
  if (!TEXT_TYPES.has(field.type)) return null;
  if (password) {
    // Only the text field that leads up to the password, not a search box elsewhere.
    return usernameBefore(inputs, password) === field ? { username: field, password } : null;
  }
  // Username-first sign-in: a lone identifier field, password on the next page.
  const texts = inputs.filter((input) => TEXT_TYPES.has(input.type));
  if (autocomplete(field).includes("username")) return { username: field, password: null };
  if (texts.length === 1 && looksLikeUsername(field)) return { username: field, password: null };
  return null;
}

/** Where a generated password goes when the user focused `field`. */
export interface NewPasswordFields {
  username: HTMLInputElement | null;
  /** The new password and its confirmation; never a "current password" field. */
  passwords: HTMLInputElement[];
  /** Sign-up or change-password form, as opposed to a lone password field. */
  signup: boolean;
}

/**
 * The fields a generated password should fill, or null when `field` is not a
 * password field or the site marks it as the current password (a sign-in form).
 */
export function newPasswordFieldsFor(field: HTMLInputElement): NewPasswordFields | null {
  if (field.type !== "password" || !usable(field)) return null;
  if (autocomplete(field).includes("current-password")) return null;
  const inputs = inputsAround(field);
  const all = inputs.filter((input) => input.type === "password");
  const marked = all.filter((input) => autocomplete(input).includes("new-password"));
  let passwords: HTMLInputElement[];
  if (marked.length > 0) passwords = marked;
  else if (all.length >= 3) passwords = all.slice(1); // current, new, repeat
  else passwords = all;
  if (!passwords.includes(field)) return null;
  return {
    username: usernameBefore(inputs, all[0] ?? field),
    passwords,
    signup: marked.length > 0 || all.length >= 2,
  };
}

export function fillNewPassword(fields: NewPasswordFields, password: string) {
  for (const input of fields.passwords) setValue(input, password);
  fields.passwords[0]?.focus();
}

/** The login form in this document to fill when the user did not pick a field. */
export function defaultLoginFields(doc: Document): LoginFields | null {
  const active = doc.activeElement;
  if (active instanceof HTMLInputElement) {
    const fields = loginFieldsFor(active);
    if (fields) return fields;
  }
  for (const input of doc.querySelectorAll("input")) {
    if (input.type !== "password" && !autocomplete(input).includes("username")) continue;
    const fields = loginFieldsFor(input);
    if (fields) return fields;
  }
  return null;
}

export function fillLogin(fields: LoginFields, username: string, password: string) {
  if (fields.username) setValue(fields.username, username);
  if (fields.password) setValue(fields.password, password);
  (fields.password ?? fields.username)?.focus();
}

/**
 * Content scripts see the native `value` setter, not the per-element one that
 * React and friends install, so assigning and then firing input/change makes
 * controlled inputs pick the value up.
 */
function setValue(input: HTMLInputElement, value: string) {
  input.focus();
  input.value = value;
  input.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

/** Inputs of the same form, or of the whole document for formless pages, in document order. */
function inputsAround(field: HTMLInputElement): HTMLInputElement[] {
  const scope: ParentNode = field.form ?? field.ownerDocument;
  return Array.from(scope.querySelectorAll("input")).filter(usable);
}

function usernameBefore(inputs: HTMLInputElement[], password: HTMLInputElement): HTMLInputElement | null {
  const before = inputs.slice(0, inputs.indexOf(password)).filter((input) => TEXT_TYPES.has(input.type));
  return before.findLast((input) => autocomplete(input).includes("username")) ?? before.at(-1) ?? null;
}

function isPassword(input: HTMLInputElement): boolean {
  return input.type === "password" && !autocomplete(input).includes("new-password");
}

function looksLikeUsername(input: HTMLInputElement): boolean {
  if (input.type === "email" || autocomplete(input).includes("email")) return true;
  const label = Array.from(input.labels ?? [], (l) => l.textContent ?? "").join(" ");
  const hints = [input.name, input.id, input.placeholder, input.getAttribute("aria-label") ?? "", label];
  return USERNAME_HINT.test(hints.join(" "));
}

function autocomplete(input: HTMLInputElement): string {
  return (input.getAttribute("autocomplete") ?? "").toLowerCase();
}

function usable(input: HTMLInputElement): boolean {
  if (input.disabled || input.readOnly || input.hidden) return false;
  const rect = input.getBoundingClientRect();
  if (rect.width < 4 || rect.height < 4) return false;
  const style = getComputedStyle(input);
  return style.visibility === "visible" && style.display !== "none" && Number(style.opacity) > 0.1;
}
