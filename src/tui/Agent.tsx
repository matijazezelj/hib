import { useEffect, useRef, useState } from "react";
import { Box, Static, Text, render, useApp, useInput } from "ink";
import type { HibClient } from "../client";
import { ensureDaemon, registerWorkspace, workspaceUrl } from "../boot";
import { SlashMenu } from "./SlashMenu";
import { bold } from "./bold";
import { isCommand, onMenuKey, suggest, type Command } from "./complete";

interface Line {
  key: number;
  text: string;
  color?: string;
  dim?: boolean;
}

interface Pending {
  id: string;
  title: string;
  ruleKey: string;
  command?: string;
}

const HELP = [
  "y / a / n         answer a permission prompt: allow once, always (this session), deny",
  "Esc               stop the running turn",
  "/auto  /manual    auto: edits in this folder and commands run without asking (network, push, publish, sudo, rm -r still ask); manual is the default",
  "/advisor          let the agent consult a model from the other provider while it works (toggle; off by default)",
  "/model <id>       switch model (same CLI keeps its native session, otherwise hands over)",
  "/models  /new  /resume  /web (open this session in the browser)  /egress (what left, and to whom)  /usage  /quit",
].join("\n");

const KIND_COLOR: Record<string, string> = { edit: "yellow", command: "blue", read: "gray", search: "gray", web: "magenta" };
let seq = 0;

function diffLines(diff: any, max = 24): Line[] {
  if (!diff) return [];
  let raw: { t: string; c?: string }[] = [];
  if (diff.unified)
    raw = String(diff.unified).split("\n").filter((t) => !t.startsWith("---") && !t.startsWith("+++")).map((t) => ({ t, c: t.startsWith("+") ? "green" : t.startsWith("-") ? "red" : t.startsWith("@@") ? "gray" : undefined }));
  else {
    if (diff.before) raw.push(...String(diff.before).split("\n").map((t) => ({ t: `-${t}`, c: "red" })));
    if (diff.after !== undefined) raw.push(...String(diff.after).replace(/\n$/, "").split("\n").map((t) => ({ t: `+${t}`, c: "green" })));
  }
  const out = raw.slice(0, max).map((x) => ({ key: seq++, text: `    ${x.t}`, color: x.c }));
  if (raw.length > max) out.push({ key: seq++, text: `    … ${raw.length - max} more lines`, color: "gray" });
  return out;
}

function App({ client, root, url, initial, initialModel }: { client: HibClient; root: string; url: string; initial?: string | true; initialModel?: string }) {
  const { exit } = useApp();
  const [lines, setLines] = useState<Line[]>([]);
  const [live, setLive] = useState("");
  const [input, setInputState] = useState("");
  const inputRef = useRef("");
  const setInput = (v: string | ((s: string) => string)) => {
    inputRef.current = typeof v === "function" ? v(inputRef.current) : v;
    setInputState(inputRef.current);
  };
  const [sid, setSid] = useState<string | undefined>();
  const sidRef = useRef<string | undefined>(undefined);
  const [model, setModel] = useState(initialModel ?? "hib/auto");
  const [busy, setBusy] = useState(false);
  const [auto, setAuto] = useState(false);
  const autoRef = useRef(false);
  const [advisor, setAdvisor] = useState(false);
  const advisorRef = useRef(false);
  const [pending, setPending] = useState<Pending[]>([]);
  const [approval, setApproval] = useState<any | null>(null);
  const [picker, setPicker] = useState<any[] | null>(null);
  const [policy, setPolicy] = useState<{ account: string } | null>(null);
  const [pickIdx, setPickIdx] = useState(0);
  const follow = useRef<AbortController | null>(null);
  const liveRef = useRef("");
  const seenCalls = useRef(new Set<string>());
  const [sel, setSel] = useState(0);
  const modelIds = useRef<string[]>([]);
  const sessionIds = useRef<string[]>([]);
  const commands: Command[] = [
    { name: "help", desc: "keys and commands" },
    { name: "model", args: "<id>", desc: "switch model for the next message", values: () => modelIds.current },
    { name: "models", desc: "list models you can switch to" },
    { name: "new", desc: "start a new session" },
    { name: "resume", args: "[id]", desc: "resume a session in this folder", values: () => sessionIds.current },
    { name: "auto", desc: "run edits and commands without asking (risky ones still ask)" },
    { name: "advisor", args: "[on|off]", desc: "let the agent consult the other provider" },
    { name: "manual", desc: "ask before every edit and command (default)" },
    { name: "stop", desc: "stop the running turn (Esc)" },
    { name: "web", desc: "browser link for this session" },
    { name: "egress", desc: "what left the machine, and to whom" },
    { name: "usage", desc: "quota per account" },
    { name: "approve", desc: "send the redacted text the guard is holding" },
    { name: "reject", desc: "cancel what the guard is holding" },
    { name: "quit", desc: "exit (the daemon and sessions keep running)" },
  ];
  const menu = suggest(input, commands);
  const q = `root=${encodeURIComponent(root)}`;

  const push = (...ls: (Line | Omit<Line, "key">)[]) => setLines((d) => [...d, ...ls.map((l) => ({ key: seq++, ...l }))]);
  const flushLive = () => {
    if (liveRef.current.trim()) push({ text: bold(liveRef.current.trim()) });
    liveRef.current = "";
    setLive("");
  };

  function apply(e: any) {
    switch (e.type) {
      case "turn_start":
        flushLive();
        setBusy(true);
        push({ text: `› ${e.text}`, color: "cyan" });
        break;
      case "user": // persisted history
        push({ text: `› ${e.text}`, color: "cyan" });
        break;
      case "assistant":
        push({ text: bold(e.text) });
        break;
      case "text":
        liveRef.current += e.delta;
        setLive(liveRef.current);
        break;
      case "ws_session":
        setModel(e.model);
        break;
      case "advisor_mode":
        advisorRef.current = e.on;
        setAdvisor(e.on);
        push({ text: e.on ? "advisor on: the agent can consult the other provider (from your next message)" : `advisor off${e.why ? `: ${e.why}` : ""}`, dim: true });
        break;
      case "advice":
        flushLive();
        push({ text: `◆ advisor ${e.model} (guard: ${e.guard})`, color: e.ok ? "magenta" : "red" }, { text: `  asked: ${e.question.replace(/\s+/g, " ").slice(0, 200)}`, dim: true }, { text: bold(e.advice) });
        break;
      case "mode":
        autoRef.current = e.auto;
        setAuto(e.auto);
        push({ text: e.auto ? "auto mode: edits and commands run without asking (network, push, publish, sudo, rm -r still ask)" : "manual mode: every edit and command asks", color: e.auto ? "yellow" : undefined, dim: !e.auto });
        break;
      case "tool_call":
        if (seenCalls.current.has(e.call.id)) break; // same call re-announced with more detail
        seenCalls.current.add(e.call.id);
        flushLive();
        push({ text: `● ${e.call.title}`, color: KIND_COLOR[e.call.kind] ?? "white" }, ...diffLines(e.call.diff));
        break;
      case "tool_result": {
        const out = String(e.output ?? "").trim().split("\n").filter(Boolean);
        const head = e.output === "declined" ? "denied" : e.ok ? "ok" : "failed";
        push({ text: `  ⎿ ${head}${out.length && e.output !== "declined" ? `: ${out[0]!.slice(0, 160)}${out.length > 1 ? ` (+${out.length - 1} lines)` : ""}` : ""}`, color: e.ok ? "gray" : "red" });
        break;
      }
      case "permission":
        flushLive();
        setPending((p) => (p.some((x) => x.id === e.id) ? p : [...p, { id: e.id, title: e.call.title, ruleKey: e.ruleKey, command: e.call.command }]));
        break;
      case "permission_answer":
        setPending((p) => p.filter((x) => x.id !== e.id));
        push({ text: `  ${e.choice === "deny" ? "✗ denied" : e.choice === "always" ? "✓ always allowed" : "✓ allowed"}`, color: e.choice === "deny" ? "red" : "green" });
        break;
      case "guard":
        if (Object.keys(e.findings).length) push({ text: `guard ${e.action}: ${Object.entries(e.findings).map(([k, v]) => `${k}×${v}`).join(" ")}`, color: "yellow" });
        break;
      case "approval":
        push({ text: `guard wants approval: ${e.reasons.join("; ")} — /approve or /reject`, color: "yellow" });
        break;
      case "sent":
        push({ text: `→ sent to ${e.account}${e.handoff ? " (with handoff transcript)" : ""}${e.progress ? " (with PROGRESS.md)" : ""}`, dim: true });
        break;
      case "handoff":
        push({ text: `handed over ${e.from} → ${e.to}`, color: "yellow" });
        break;
      case "rate_limited":
      case "error":
        flushLive();
        push({ text: e.message, color: "red" });
        break;
      case "turn_end":
        flushLive();
        setBusy(false);
        setPending([]);
        break;
    }
  }

  /** Shows a session's history, then follows it live (turns from the web show up here too). */
  async function attach(id: string, quiet = false) {
    follow.current?.abort();
    const ac = new AbortController();
    follow.current = ac;
    sidRef.current = id;
    setSid(id);
    const snap = await client.get(`/ws/sessions/${id}?${q}`);
    if (!quiet) {
      push({ text: `session ${id} · ${snap.row?.title ?? ""}`, dim: true });
      for (const e of snap.events) apply(e);
      for (const e of snap.live) apply(e);
    }
    if (snap.row?.model) setModel(snap.row.model);
    setBusy(snap.running);
    autoRef.current = !!snap.auto;
    setAuto(!!snap.auto);
    advisorRef.current = !!snap.advisor;
    setAdvisor(!!snap.advisor);
    let after = quiet ? 0 : snap.seq;
    (async () => {
      while (!ac.signal.aborted) {
        try {
          for await (const e of client.stream(`/ws/sessions/${id}/stream?${q}&after=${after}`, ac.signal)) {
            after = e.seq;
            apply(e);
          }
        } catch {
          if (ac.signal.aborted) return;
        }
        await Bun.sleep(1000); // daemon restarted or connection dropped: reconnect and catch up
      }
    })();
  }

  async function openPicker() {
    const list = await client.get(`/ws/sessions?${q}`);
    sessionIds.current = list.map((s: any) => s.id);
    if (!list.length) return push({ text: "no sessions in this folder yet", dim: true });
    setPicker(list);
    setPickIdx(0);
  }

  useEffect(() => {
    push({ text: `hib · ${root}`, color: "cyan" }, { text: "describe a task; /help for commands", dim: true });
    client.get("/hib/info").then((i) => (modelIds.current = (i.models as string[]).filter((m) => /^(claude|codex)@/.test(m)))).catch(() => {});
    client.get(`/ws/sessions?${q}`).then((l) => (sessionIds.current = l.map((s: any) => s.id))).catch(() => {});
    client.get(`/ws/tree?${q}`).then((t) => {
      if (t.policy) modelIds.current = modelIds.current.filter((m) => m.startsWith(t.policy.account + "/"));
      if (!t.policy) return;
      setPolicy(t.policy);
      push({ text: `sensitive workspace: only ${t.policy.account} sees this folder; every read asks; secrets are blocked`, color: "yellow" });
    }).catch(() => {});
    if (initial === true) openPicker();
    else if (initial) attach(initial).catch((e) => push({ text: String(e.message), color: "red" }));
    const t = setInterval(async () => {
      const list = await client.get("/hib/approvals").catch(() => []);
      setApproval(list[0] ?? null);
    }, 1000);
    return () => {
      clearInterval(t);
      follow.current?.abort();
    };
  }, []);

  async function answer(choice: "allow" | "always" | "deny") {
    const p = pending[0];
    if (!p || !sidRef.current) return;
    await client.post(`/ws/permission?${q}`, { sessionId: sidRef.current, id: p.id, choice }).catch((e) => push({ text: e.message, color: "red" }));
  }

  async function interrupt() {
    if (sidRef.current) await client.post(`/ws/interrupt?${q}`, { sessionId: sidRef.current }).catch(() => {});
  }

  async function command(line: string): Promise<boolean> {
    const [c, ...args] = line.slice(1).split(" ");
    const arg = args.join(" ").trim();
    switch (c) {
      case "help":
        push({ text: HELP, dim: true });
        return true;
      case "quit":
      case "exit":
        follow.current?.abort();
        exit();
        setTimeout(() => process.exit(0), 50);
        return true;
      case "model":
        if (!arg) push({ text: `model: ${model}`, dim: true });
        else {
          setModel(arg);
          push({ text: `model → ${arg} (applies to the next message)`, dim: true });
        }
        return true;
      case "models":
        push({ text: (await client.get("/hib/info")).models.filter((m: string) => /^(claude|codex)@/.test(m) && (!policy || m.startsWith(policy.account + "/"))).join("\n"), dim: true });
        return true;
      case "auto":
      case "manual": {
        const on = c === "auto";
        if (sidRef.current) await client.post(`/ws/mode?${q}`, { sessionId: sidRef.current, auto: on }).catch((e) => push({ text: e.message, color: "red" }));
        else apply({ type: "mode", auto: on });
        return true;
      }
      case "advisor": {
        const on = arg ? arg !== "off" : !advisorRef.current;
        if (on && policy) return push({ text: "advisor is not available in sensitive folders", color: "yellow" }), true;
        if (sidRef.current) await client.post(`/ws/advisor?${q}`, { sessionId: sidRef.current, on }).catch((e) => push({ text: e.message, color: "red" }));
        else apply({ type: "advisor_mode", on });
        return true;
      }
      case "new":
        follow.current?.abort();
        sidRef.current = undefined;
        setSid(undefined);
        autoRef.current = false;
        setAuto(false);
        advisorRef.current = false;
        setAdvisor(false);
        push({ text: "new session (starts with your next message)", dim: true });
        return true;
      case "resume":
        if (arg) await attach(arg).catch((e) => push({ text: e.message, color: "red" }));
        else await openPicker();
        return true;
      case "stop":
        await interrupt();
        return true;
      case "egress": {
        if (!sidRef.current) return push({ text: "no session yet", dim: true }), true;
        for (const t of await client.get(`/ws/egress/${sidRef.current}?${q}`)) {
          push({ text: `→ ${t.account}${t.handoff ? " (+ handoff transcript)" : ""}: ${t.prompt.replace(/\s+/g, " ").slice(0, 120)}`, color: "cyan" });
          if (t.guard) push({ text: `   guard: ${t.guard}`, color: "yellow" });
          for (const a of t.actions) push({ text: `   ${a.status.padEnd(9)} ${a.kind.padEnd(7)} ${a.title}`, dim: a.status !== "done", color: a.status === "failed" ? "red" : undefined });
        }
        return true;
      }
      case "web":
        push({ text: workspaceUrl(url, root, sidRef.current), color: "cyan" });
        return true;
      case "usage":
        for (const u of await client.get("/hib/usage"))
          push({ text: `${u.account}: ${u.windows.map((w: any) => `${w.window} ${Math.round(w.usedPct * 100)}%`).join("  ") || "no data"}${u.cooldownUntil ? " (cooling down)" : ""}`, dim: true });
        return true;
      case "approve":
      case "reject":
        if (!approval) push({ text: "no pending guard approval", color: "red" });
        else await client.post(`/hib/approvals/${approval.id}`, { approve: c === "approve" });
        return true;
    }
    push({ text: `unknown command /${c} — /help`, color: "red" });
    return true;
  }

  async function submit(text: string) {
    if (!text.trim()) return;
    if (isCommand(text)) return void (await command(text.trim()));
    if (busy) return push({ text: "a turn is running; wait, or Esc to stop it", color: "yellow" });
    try {
      const r = await client.post<{ sessionId: string }>(`/ws/turn?${q}`, { sessionId: sidRef.current, model, text, auto: autoRef.current, advisor: advisorRef.current });
      if (r.sessionId !== sidRef.current) await attach(r.sessionId, true);
    } catch (e: any) {
      push({ text: e.message, color: "red" });
    }
  }

  useInput((ch, key) => {
    if (picker) {
      if (key.upArrow) setPickIdx((i) => Math.max(0, i - 1));
      else if (key.downArrow) setPickIdx((i) => Math.min(picker.length - 1, i + 1));
      else if (key.return) {
        const id = picker[pickIdx].id;
        setPicker(null);
        attach(id).catch((e) => push({ text: e.message, color: "red" }));
      } else if (key.escape) setPicker(null);
      return;
    }
    if (key.ctrl && ch === "c") {
      if (busy) return void interrupt();
      follow.current?.abort();
      exit();
      setTimeout(() => process.exit(0), 50);
      return;
    }
    const items = suggest(inputRef.current, commands);
    if (key.escape) return busy ? void interrupt() : setInput(""); // stop a running turn, else clear the line
    if (pending.length && !inputRef.current && ["y", "a", "n"].includes(ch)) return void answer(ch === "y" ? "allow" : ch === "a" ? "always" : "deny");
    if (items.length && (key.tab || key.upArrow || key.downArrow)) {
      const r = onMenuKey(key.tab ? "tab" : key.upArrow ? "up" : "down", inputRef.current, items, sel);
      if (r.input !== undefined) setInput(r.input);
      if (r.selected !== undefined) setSel(r.selected);
      return;
    }
    if (key.backspace || key.delete) return setInput((s) => s.slice(0, -1)), setSel(0);
    const chunk = key.return ? "\r" : ch;
    if (!chunk || key.ctrl || key.meta) return;
    // Fast typing and pastes arrive as one chunk, so newlines are handled inside chunks too.
    const body = chunk.replace(/\r\n?/g, "\n");
    if (body.endsWith("\n") && !body.slice(0, -1).includes("\n")) {
      const t = inputRef.current + body.slice(0, -1);
      const r = onMenuKey("enter", t, suggest(t, commands), sel);
      setSel(0);
      if (!r.submit) return setInput(r.input ?? t); // completed a command that still needs an argument
      setInput("");
      submit(r.input ?? t);
    } else {
      setInput((s) => s + body);
      setSel(0);
    }
  });

  const rule = (k: string) => k.replace(/^(Bash|command):exact:.*/, "this exact command").replace(/^(Bash|command):/, "").replace(/^edit$/, "edits in this folder");

  return (
    <>
      <Static items={lines}>
        {(l) => (
          <Text key={l.key} color={l.color} dimColor={l.dim}>
            {l.text}
          </Text>
        )}
      </Static>
      {live && <Text>{bold(live)}</Text>}
      {picker && (
        <Box flexDirection="column" borderStyle="round" paddingX={1}>
          <Text bold>Resume a session in this folder (↑/↓, enter, esc)</Text>
          {picker.slice(0, 20).map((s, i) => (
            <Text key={s.id} inverse={i === pickIdx}>
              {new Date(s.updated).toLocaleString()}  {String(s.model ?? "-").padEnd(26)} {s.running ? "(running) " : ""}{s.title}
            </Text>
          ))}
        </Box>
      )}
      {pending[0] && (
        <Box flexDirection="column" borderStyle="round" borderColor="yellow" paddingX={1}>
          <Text color="yellow">Allow {pending[0].title}?</Text>
          {pending[0].command && <Text>{pending[0].command}</Text>}
          <Text>
            <Text bold>y</Text> allow once  <Text bold>a</Text> always allow {rule(pending[0].ruleKey)}  <Text bold>n</Text> deny
            {pending.length > 1 ? <Text dimColor>  (+{pending.length - 1} more)</Text> : null}
          </Text>
        </Box>
      )}
      {approval && (
        <Box borderStyle="round" borderColor="yellow" paddingX={1}>
          <Text color="yellow">Guard: {approval.reasons.join("; ")} — /approve sends the redacted text, /reject cancels</Text>
        </Box>
      )}
      <Text dimColor>
        [{model}{sid ? ` · ${sid}` : ""}{policy ? ` · sensitive → ${policy.account}` : ""}{auto ? " · auto" : ""}{advisor ? " · advisor" : ""}] {busy ? "working… (esc to stop)" : ""}
      </Text>
      <Box>
        <Text color="cyan">› </Text>
        <Text>{input}</Text>
        <Text inverse> </Text>
      </Box>
      <SlashMenu items={menu} selected={sel} />
    </>
  );
}

export async function runAgent(opts: { dir: string; resume?: string | true; model?: string }) {
  const d = await ensureDaemon();
  if (d.started) console.log(`(started hib daemon at ${d.url}; logs in ~/.hib/daemon.log)`);
  const root = await registerWorkspace(d.client, opts.dir);
  render(<App client={d.client} root={root} url={d.url} initial={opts.resume} initialModel={opts.model} />, { exitOnCtrlC: false });
}
