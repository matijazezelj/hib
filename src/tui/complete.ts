// Slash-command autocomplete shared by the terminal UIs.

export interface Command {
  name: string;
  args?: string; // shown as a hint, e.g. "<id>"
  desc: string;
  values?: () => string[]; // completions for the first argument
}

export interface Suggestion {
  label: string; // what is shown
  insert: string; // what the input becomes when chosen
  desc: string;
  complete: boolean; // true when choosing it leaves a runnable line (no argument still required)
}

const MAX = 8;

/** Suggestions for the current input, or [] when no menu should show. */
export function suggest(input: string, commands: Command[]): Suggestion[] {
  if (!input.startsWith("/") || input.includes("\n")) return [];
  const space = input.indexOf(" ");
  if (space < 0) {
    const typed = input.slice(1).toLowerCase();
    if (/[/.~]/.test(typed)) return []; // a path like /etc/hosts is a message, not a command
    const starts = commands.filter((c) => c.name.toLowerCase().startsWith(typed));
    const contains = commands.filter((c) => !starts.includes(c) && typed && c.name.toLowerCase().includes(typed));
    return [...starts, ...contains].slice(0, MAX).map((c) => ({
      label: `/${c.name}${c.args ? ` ${c.args}` : ""}`,
      insert: `/${c.name}${c.args || c.values ? " " : ""}`,
      desc: c.desc,
      complete: !c.args || c.args.startsWith("["),
    }));
  }
  // First argument: complete from the command's known values (models, session ids…).
  const cmd = commands.find((c) => c.name === input.slice(1, space));
  if (!cmd?.values) return [];
  const arg = input.slice(space + 1);
  if (arg.includes(" ")) return [];
  const vals = cmd.values();
  const starts = vals.filter((v) => v.startsWith(arg));
  const contains = vals.filter((v) => !starts.includes(v) && arg && v.includes(arg));
  const out = [...starts, ...contains];
  if (out.length === 1 && out[0] === arg) return []; // already complete
  return out.slice(0, MAX).map((v) => ({ label: v, insert: `/${cmd.name} ${v}`, desc: "", complete: true }));
}

/** "/model x" is a command; "/etc/hosts is broken" is a message that happens to start with a slash. */
export function isCommand(line: string): boolean {
  return /^\/[\w+-]+(\s|$)/.test(line.trim()) && !/^\/[\w+-]*[/.~]/.test(line.trim());
}

/** Longest common prefix of the suggestions' inserts, used for Tab when several match. */
export function commonPrefix(s: Suggestion[]): string {
  if (!s.length) return "";
  let p = s[0]!.insert;
  for (const x of s.slice(1)) while (!x.insert.startsWith(p)) p = p.slice(0, -1);
  return p;
}

/**
 * What a key does while the menu is open. Tab completes (the selection, or the common prefix when
 * several match); Enter runs a finished command line or completes a partial one; ↑/↓ move.
 */
export function onMenuKey(
  key: "tab" | "enter" | "up" | "down",
  input: string,
  items: Suggestion[],
  selected: number,
): { input?: string; selected?: number; submit?: boolean } {
  if (!items.length) return key === "enter" ? { submit: true } : {};
  const cur = items[Math.min(selected, items.length - 1)]!;
  if (key === "up") return { selected: (selected - 1 + items.length) % items.length };
  if (key === "down") return { selected: (selected + 1) % items.length };
  if (key === "tab") {
    const prefix = commonPrefix(items);
    return { input: items.length > 1 && prefix.length > input.length && selected === 0 ? prefix : cur.insert, selected: 0 };
  }
  // Enter: if the typed text is already exactly a runnable command, run it; otherwise take the selection.
  const typedName = input.trim();
  const exact = items.find((s) => s.insert.trim() === typedName && s.complete);
  if (exact) return { submit: true };
  if (cur.complete) return { input: cur.insert.trim(), submit: true };
  return { input: cur.insert, selected: 0 };
}
