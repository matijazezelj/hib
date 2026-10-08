import { describe, expect, test } from "bun:test";
import { isCommand, onMenuKey, suggest, type Command } from "../src/tui/complete";

const cmds: Command[] = [
  { name: "help", desc: "help" },
  { name: "model", args: "<id>", desc: "switch model", values: () => ["claude@default/haiku", "claude@default/sonnet", "codex@default/gpt-6-luna"] },
  { name: "models", desc: "list models" },
  { name: "resume", args: "[id]", desc: "resume", values: () => ["w_aaa", "w_bbb"] },
  { name: "quit", desc: "quit" },
  { name: "commit", desc: "plugin skill" },
];

describe("slash suggestions", () => {
  test("paths are messages, never commands", () => {
    for (const c of ["/model x", "/quit", "/+", "/commit fix the bug", "/resume w_1"]) expect(isCommand(c)).toBe(true);
    for (const m of ["/etc/hosts is broken", "/Users/me/a.ts fails", "/tmp/x", "hello /quit"]) expect(isCommand(m)).toBe(false);
    expect(suggest("/etc/hosts", cmds)).toEqual([]);
    expect(suggest("/Users/x.ts", cmds)).toEqual([]);
  });
  test("only for slash input", () => {
    expect(suggest("hello", cmds)).toEqual([]);
    expect(suggest("/", cmds).length).toBe(6);
  });
  test("prefix matches first, then substring", () => {
    expect(suggest("/mo", cmds).map((s) => s.label)).toEqual(["/model <id>", "/models"]);
    expect(suggest("/it", cmds).map((s) => s.label)).toEqual(["/quit", "/commit"]);
  });
  test("argument values", () => {
    expect(suggest("/model so", cmds).map((s) => s.label)).toEqual(["claude@default/sonnet"]);
    expect(suggest("/model codex", cmds)[0]!.insert).toBe("/model codex@default/gpt-6-luna");
    expect(suggest("/model claude@default/haiku", cmds)).toEqual([]); // already complete
    expect(suggest("/help x", cmds)).toEqual([]);
  });
});

describe("menu keys", () => {
  test("tab completes the common prefix, then the selection", () => {
    const items = suggest("/mo", cmds);
    expect(onMenuKey("tab", "/mo", items, 0).input).toBe("/model");
    expect(onMenuKey("tab", "/model", suggest("/model", cmds), 1).input).toBe("/models");
  });
  test("enter runs an exact command, completes one that needs an argument", () => {
    expect(onMenuKey("enter", "/models", suggest("/models", cmds), 0)).toEqual({ submit: true });
    expect(onMenuKey("enter", "/mod", suggest("/mod", cmds), 0)).toEqual({ input: "/model ", selected: 0 });
    expect(onMenuKey("enter", "/qu", suggest("/qu", cmds), 0)).toEqual({ input: "/quit", submit: true });
    expect(onMenuKey("enter", "/model so", suggest("/model so", cmds), 0)).toEqual({ input: "/model claude@default/sonnet", submit: true });
  });
  test("arrows wrap", () => {
    const items = suggest("/mo", cmds);
    expect(onMenuKey("up", "/mo", items, 0).selected).toBe(1);
    expect(onMenuKey("down", "/mo", items, 1).selected).toBe(0);
  });
});
