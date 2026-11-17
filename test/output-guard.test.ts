import { describe, expect, test } from "bun:test";
import { existsSync, linkSync, mkdtempSync, readFileSync, realpathSync, renameSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Vault } from "../src/guard/vault";
import { capturePath, ClaudeDriver, claudeLaunch, makeCapture, readCapture, wrapCommand } from "../src/workspace/claude-driver";
import { Queue } from "../src/workspace/queue";

const tmp = () => realpathSync(mkdtempSync(join(tmpdir(), "hib-og-")));

describe("Vault.knownFindings", () => {
  test("a value the vault already holds gets its token again, whole words only", () => {
    const v = new Vault("abcd");
    const t = v.token("PERSON", "Ivana Babic");
    v.token("EMAIL", "ana@x.io");
    v.token("USER", "ab"); // too short to look for
    const text = "Ivana Babic wrote to ana@x.io; Ivana Babicova and xIvana Babic aren't her; ab";
    const f = v.knownFindings(text);
    expect(f.map((x) => [x.value, x.category])).toEqual([["Ivana Babic", "PERSON"], ["ana@x.io", "EMAIL"]]);
    expect(v.replace(text, f)).toStartWith(`[${t}] wrote to [`);
    expect(new Vault().knownFindings("anything")).toEqual([]);
  });

  test("regex characters in values are literal", () => {
    const v = new Vault("abcd");
    v.token("TERM", "a+b (c)");
    expect(v.knownFindings("x a+b (c) y aab (c)").map((f) => f.start)).toEqual([2]);
  });
});

describe("capture files", () => {
  test("wrapCommand: eval of one quoted string in a subshell, into the file; then only the exit status", () => {
    const dir = tmp();
    const run = (cmd: string) => {
      const f = join(dir, "a");
      const r = Bun.spawnSync(["bash", "-c", wrapCommand(cmd, f)]);
      return { out: r.stdout.toString(), file: readFileSync(f, "utf8") };
    };
    expect(run("echo out; echo err >&2; exit 3")).toEqual({ out: "[exit 3]\n", file: "out\nerr\n" });
    // a ")" can't close hib's subshell and print past the redirect
    expect(run("true )\necho escaped; exit 3\n( true")).toMatchObject({ out: expect.stringMatching(/^\[exit [1-9]\d*\]\n$/) });
    expect(run("echo 'it''s' \"q'\"; cat <<EOF\nhere ) doc\nEOF")).toEqual({ out: "[exit 0]\n", file: "its q'\nhere ) doc\n" });
  });

  test("capturePath keeps only safe characters from the call id", () => {
    expect(capturePath("/c", "toolu_01AbC")).toBe("/c/toolu_01AbC");
    expect(capturePath("/c", "../x'; rm -rf ~")).toBe("/c/xrm-rf");
    expect(capturePath("/c")).toMatch(/^\/c\/call_[0-9a-f]{8}$/);
  });

  test("readCapture: only the file hib made; reads, removes, cuts at a line; refuses swaps, symlinks and hard links", () => {
    const dir = tmp();
    const made = (n: string, text: string) => {
      const pin = makeCapture(join(dir, n));
      writeFileSync(join(dir, n), text);
      return pin;
    };
    expect(readCapture(dir, "a", made("a", "hello\n"))).toBe("hello\n");
    expect(existsSync(join(dir, "a"))).toBe(false);
    expect(readCapture(dir, "k", made("k", "kept"), false)).toBe("kept");
    expect(existsSync(join(dir, "k"))).toBe(true);
    expect(readCapture(dir, "missing", { dev: 0, ino: 0 })).toBe("");
    writeFileSync(join(dir, "nopin"), "x");
    expect(readCapture(dir, "nopin", undefined)).toContain("didn't run through hib's capture");
    const secret = join(dir, "..", `${dir.split("/").pop()}-secret.csv`);
    writeFileSync(secret, "TOP SECRET");
    // a data file renamed onto the capture path passes every check but the pin
    const pin = makeCapture(join(dir, "r"));
    renameSync(secret, join(dir, "r"));
    expect(readCapture(dir, "r", pin)).toContain("replaced");
    writeFileSync(secret, "TOP SECRET");
    const p2 = makeCapture(join(dir, "s"));
    rmSync(join(dir, "s"));
    symlinkSync(secret, join(dir, "s"));
    expect(readCapture(dir, "s", p2)).not.toContain("TOP SECRET");
    const p3 = made("h", "x");
    linkSync(join(dir, "h"), join(dir, "h2"));
    expect(readCapture(dir, "h", p3)).toContain("replaced");
    const big = readCapture(dir, "big", made("big", ("a@b.co ".repeat(9) + "\n").repeat(1000)));
    expect(big.length).toBeLessThan(61_000);
    expect(big).toContain("bytes in all");
    expect(big.split("\n").slice(0, -2).every((l) => l === "a@b.co ".repeat(9))).toBe(true); // whole lines only
  });

  test("makeCapture replaces whatever is at the path with a fresh file", () => {
    const dir = tmp();
    symlinkSync("/etc/passwd", join(dir, "x"));
    const pin = makeCapture(join(dir, "x"));
    expect(statSync(join(dir, "x")).ino).toBe(pin.ino);
    expect(statSync(join(dir, "x")).size).toBe(0);
  });
});

describe("claude driver with a capture folder", () => {
  const driver = (captureDir: string) => {
    const d = new ClaudeDriver() as any;
    d.q = new Queue<any>();
    d.captureDir = captureDir;
    d.sent = [] as any[];
    d.send = (m: any) => d.sent.push(m);
    return d;
  };

  test("launch: the sandbox may write the folder; the file tools can't read it; no Monitor", () => {
    const account = { id: "claude@w", provider: "claude", name: "w", env: {}, limits: {}, dirs: [] };
    const { args } = claudeLaunch({ cwd: "/work", model: "m", account, askReads: true, sandbox: { denyRead: [] }, captureDir: "/tmp/hib-out-1/w_1" } as any);
    const s = JSON.parse(args[args.indexOf("--settings") + 1]!);
    expect(s.sandbox.filesystem.allowWrite).toEqual(["/tmp/hib-out-1/w_1"]);
    expect(s.permissions.deny).toEqual(expect.arrayContaining(["Read(//tmp/hib-out-1/w_1)", "Read(//tmp/hib-out-1/w_1/**)", "Monitor"]));
    const plain = claudeLaunch({ cwd: "/work", model: "m", account, sandbox: { denyRead: [] } } as any).args;
    expect(JSON.parse(plain[plain.indexOf("--settings") + 1]!).sandbox.filesystem.allowWrite).toBeUndefined();
  });

  test("every allowed Bash call is wrapped and kept in the foreground; other tools aren't", () => {
    const dir = tmp();
    const d = driver(dir);
    d.onMessage({ type: "control_request", request_id: "r1", request: { subtype: "can_use_tool", tool_name: "Bash", tool_use_id: "toolu_9", input: { command: "ls", run_in_background: true } } });
    d.answer("cl_r1", { behavior: "allow" });
    const input = d.sent[0].response.response.updatedInput;
    expect(input).toEqual({ command: wrapCommand("ls", join(dir, "toolu_9")), run_in_background: false });
    d.onMessage({ type: "control_request", request_id: "r2", request: { subtype: "can_use_tool", tool_name: "Read", tool_use_id: "toolu_8", input: { file_path: "/a" } } });
    d.answer("cl_r2", { behavior: "allow" });
    expect(d.sent[1].response.response.updatedInput).toEqual({ file_path: "/a" });
    d.onMessage({ type: "control_request", request_id: "r3", request: { subtype: "can_use_tool", tool_name: "Bash", tool_use_id: "toolu_7", input: { command: "rm x" } } });
    d.answer("cl_r3", { behavior: "deny", message: "no" });
    expect(d.sent[2].response.response).toEqual({ behavior: "deny", message: "no" });
  });

  test("the hook hands the captured output (plus anything else the tool printed) to hib, and sends back only its answer", () => {
    const dir = tmp();
    const d = driver(dir);
    d.onMessage({ type: "control_request", request_id: "r1", request: { subtype: "can_use_tool", tool_name: "Bash", tool_use_id: "toolu_9", input: { command: "cat x" } } });
    d.answer("cl_r1", { behavior: "allow" });
    d.sent.length = 0;
    writeFileSync(join(dir, "toolu_9"), "jane@acme.com\n");
    const tr = { stdout: "[exit 0]", stderr: "", interrupted: false, isImage: false, noOutputExpected: false };
    d.onMessage({ type: "control_request", request_id: "h1", request: { subtype: "hook_callback", callback_id: "hib_output", input: { hook_event_name: "PostToolUse", tool_name: "Bash", tool_use_id: "toolu_9", tool_response: tr } } });
    const ev = d.q.items.at(-1);
    expect(ev).toEqual({ type: "output", id: "out_h1", callId: "toolu_9", text: "jane@acme.com\n\n[exit 0]" });
    expect(d.sent).toEqual([]); // the CLI waits
    d.answerOutput("out_h1", "[EMAIL]\n[exit 0]");
    expect(d.sent[0]).toEqual({ type: "control_response", response: { subtype: "success", request_id: "h1", response: { hookSpecificOutput: { hookEventName: "PostToolUse", updatedToolOutput: { ...tr, stdout: "[EMAIL]\n[exit 0]" } } } } });
    // another tool's hook is answered at once and left alone
    d.onMessage({ type: "control_request", request_id: "h2", request: { subtype: "hook_callback", callback_id: "hib_output", input: { hook_event_name: "PostToolUse", tool_name: "Read", tool_response: {} } } });
    expect(d.sent[1].response).toEqual({ subtype: "success", request_id: "h2", response: {} });
  });

  test("a hook outside a turn is answered with the output withheld", () => {
    const d = driver(tmp());
    d.q = undefined;
    d.onMessage({ type: "control_request", request_id: "h1", request: { subtype: "hook_callback", callback_id: "hib_output", input: { hook_event_name: "PostToolUse", tool_name: "Bash", tool_response: { stdout: "raw", stderr: "raw2" } } } });
    expect(d.sent[0].response.response.hookSpecificOutput.updatedToolOutput).toMatchObject({ stdout: "[hib withheld this output]", stderr: "" });
  });

  test("the session doesn't start unless Claude Code confirms the hook", async () => {
    for (const reply of [{ subtype: "success", response: { hooks_applied: false } }, { subtype: "error", error: "unknown" }]) {
      const d = driver(tmp());
      let killed = false;
      d.proc = { kill: () => (killed = true) };
      d.send = (m: any) => queueMicrotask(() => d.onMessage({ type: "control_response", response: { ...reply, request_id: m.request_id } }));
      await expect(d.registerOutputHook()).rejects.toThrow("command-output guard");
      expect(killed).toBe(true);
    }
    const ok = driver(tmp());
    let req: any;
    ok.send = (m: any) => ((req = m), queueMicrotask(() => ok.onMessage({ type: "control_response", response: { subtype: "success", request_id: m.request_id, response: { hooks_applied: true } } })));
    await ok.registerOutputHook();
    expect(req.request).toEqual({ subtype: "initialize", hooks: { PostToolUse: [{ matcher: "Bash", hookCallbackIds: ["hib_output"], timeout: 600 }] } });
  });
});
