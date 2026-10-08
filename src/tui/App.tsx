import { useEffect, useRef, useState } from "react";
import { Box, Static, Text, render, useApp, useInput } from "ink";
import type { HibClient } from "../client";
import type { HibEvent } from "../engine";
import { connect } from "../boot";
import { SlashMenu } from "./SlashMenu";
import { bold } from "./bold";
import { isCommand, onMenuKey, suggest, type Command } from "./complete";

interface Line {
  key: number;
  kind: "user" | "assistant" | "note" | "error" | "meta";
  text: string;
}

const HELP = [
  "/model <id>        switch model (keeps the conversation) — /models lists them",
  "/mode chat | agent <dir>",
  "/new  /resume      new conversation / pick one to resume",
  "/arena             run the next message head-to-head; /pick a|b to choose",
  "/+  /-             rate the last answer",
  "/approve  /reject  answer a pending guard approval (/edit <text> to send edited)",
  "/usage  /quit      plus any plugin skill as /<name> args",
].join("\n");

let seq = 0;

function App({ client, initialResume, initialModel }: { client: HibClient; initialResume?: string | true; initialModel?: string }) {
  const { exit } = useApp();
  const [done, setDone] = useState<Line[]>([]); // finished lines, printed once
  const [live, setLive] = useState(""); // streaming answer
  const [input, setInputState] = useState("");
  const inputRef = useRef(""); // keystrokes can arrive faster than re-renders
  const setInput = (v: string | ((s: string) => string)) => {
    inputRef.current = typeof v === "function" ? v(inputRef.current) : v;
    setInputState(inputRef.current);
  };
  const skills = useRef<Set<string>>(new Set());
  const skillInfo = useRef<{ name: string; description?: string }[]>([]);
  const modelIds = useRef<string[]>([]);
  const convIds = useRef<string[]>([]);
  const [sel, setSel] = useState(0);
  const commands = (): Command[] => [
    { name: "help", desc: "keys and commands" },
    { name: "model", args: "<id>", desc: "switch model (keeps the conversation)", values: () => modelIds.current },
    { name: "models", desc: "list models" },
    { name: "mode", args: "chat | agent [dir]", desc: "tools off, or agent in a folder", values: () => ["chat", "agent"] },
    { name: "new", desc: "new conversation" },
    { name: "resume", args: "[id]", desc: "resume a conversation", values: () => convIds.current },
    { name: "arena", desc: "run the next message head-to-head" },
    { name: "pick", args: "a | b", desc: "choose the better arena answer", values: () => ["a", "b"] },
    { name: "+", desc: "rate the last answer up" },
    { name: "-", desc: "rate the last answer down" },
    { name: "approve", desc: "send what the guard is holding" },
    { name: "edit", args: "<text>", desc: "send an edited version instead" },
    { name: "reject", desc: "cancel what the guard is holding" },
    { name: "usage", desc: "quota per account" },
    { name: "quit", desc: "exit" },
    ...skillInfo.current.map((s) => ({ name: s.name, args: "[args]", desc: `skill: ${s.description ?? ""}` })),
  ];
  const [busy, setBusy] = useState(false);
  const [model, setModel] = useState(initialModel ?? "hib/auto");
  const [mode, setMode] = useState<{ mode: "chat" | "agent"; cwd?: string }>({ mode: "chat" });
  const [convId, setConvId] = useState<string | undefined>();
  const [picker, setPicker] = useState<any[] | null>(null);
  const [pickIdx, setPickIdx] = useState(0);
  const [approval, setApproval] = useState<any | null>(null);
  const [status, setStatus] = useState("");
  const lastRun = useRef<string | undefined>(undefined);
  const arenaNext = useRef(false);
  const lastArena = useRef<Extract<HibEvent, { type: "arena" }> | null>(null);
  const abort = useRef<AbortController | null>(null);

  const push = (kind: Line["kind"], text: string) => setDone((d) => [...d, { key: seq++, kind, text }]);

  useEffect(() => {
    if (initialResume === true) openPicker();
    else if (initialResume) resume(initialResume);
    else push("note", "hib — type a message, /help for commands");
    client.get("/hib/info").then((i) => {
      skills.current = new Set(i.skills.map((s: any) => s.name));
      skillInfo.current = i.skills;
      modelIds.current = i.models;
    }).catch(() => {});
    client.get("/hib/conversations").then((l) => (convIds.current = l.map((c: any) => c.id))).catch(() => {});
    const t = setInterval(async () => {
      const list = await client.get("/hib/approvals").catch(() => []);
      setApproval(list[0] ?? null);
    }, 1000);
    return () => clearInterval(t);
  }, []);

  async function openPicker() {
    const list = await client.get("/hib/conversations");
    if (!list.length) return push("note", "no saved conversations");
    setPicker(list);
    setPickIdx(0);
  }

  async function resume(id: string) {
    const c = await client.get(`/hib/conversations/${id}`).catch(() => null);
    if (!c) return push("error", `no conversation ${id}`);
    setConvId(id);
    push("note", `resumed "${c.title}" (${c.messages.length} messages, last model ${c.last_model ?? "-"})`);
    for (const m of c.messages.slice(-10)) push(m.role === "user" ? "user" : "assistant", m.content);
    if (c.messages.length > 10) push("note", `(${c.messages.length - 10} earlier messages not shown)`);
  }

  async function command(line: string): Promise<boolean> {
    const [c, ...args] = line.slice(1).split(" ");
    const arg = args.join(" ").trim();
    switch (c) {
      case "help":
        push("note", HELP);
        return true;
      case "quit":
      case "exit":
        exit();
        setTimeout(() => process.exit(0), 50);
        return true;
      case "model":
        if (!arg) return push("note", `model: ${model}`), true;
        setModel(arg);
        push("note", `model → ${arg}${convId ? " (history carries over)" : ""}`);
        return true;
      case "models":
        push("note", (await client.get("/hib/info")).models.join("\n"));
        return true;
      case "mode":
        if (args[0] === "agent") {
          setMode({ mode: "agent", cwd: args[1] ?? process.cwd() });
          push("note", `agent mode in ${args[1] ?? process.cwd()} (dir must be in guard.agentDirs)`);
        } else {
          setMode({ mode: "chat" });
          push("note", "chat mode (no tools)");
        }
        return true;
      case "new":
        setConvId(undefined);
        push("note", "new conversation");
        return true;
      case "resume":
        if (arg) await resume(arg);
        else await openPicker();
        return true;
      case "arena":
        arenaNext.current = true;
        push("note", "next message runs head-to-head");
        return true;
      case "pick": {
        const a = lastArena.current;
        if (!a || (arg !== "a" && arg !== "b")) return push("error", "usage: /pick a|b after an arena answer"), true;
        await client.post(`/hib/arena/${a.id}`, { winner: arg });
        push("note", `picked ${a[arg].model}`);
        lastArena.current = null;
        return true;
      }
      case "+":
      case "-":
        if (!lastRun.current) return push("error", "nothing to rate yet"), true;
        await client.post("/hib/feedback", { runId: lastRun.current, value: c === "+" ? 1 : -1 });
        push("note", c === "+" ? "rated up" : "rated down");
        return true;
      case "approve":
      case "reject":
      case "edit":
        if (!approval) return push("error", "no pending approval"), true;
        await client.post(`/hib/approvals/${approval.id}`, { approve: c !== "reject", edited: c === "edit" ? arg : undefined });
        setApproval(null);
        return true;
      case "usage":
        for (const u of await client.get("/hib/usage"))
          push("note", `${u.account}: ${u.windows.map((w: any) => `${w.window} ${Math.round(w.usedPct * 100)}%`).join("  ") || "no data"}${u.cooldownUntil ? " (cooling down)" : ""}`);
        return true;
    }
    if (skills.current.has(c!)) return false; // plugin skill: the engine expands it
    push("error", `unknown command /${c} — /help lists commands`);
    return true;
  }

  async function submit(text: string) {
    if (!text.trim()) return;
    if (isCommand(text) && (await command(text.trim()))) return;
    push("user", text);
    setBusy(true);
    const ac = new AbortController();
    abort.current = ac;
    let acc = "";
    let revising = false;
    try {
      for await (const e of client.chat({ conversationId: convId, messages: [{ role: "user", content: text }], model, mode: mode.mode, cwd: mode.cwd, arena: arenaNext.current }, ac.signal)) {
        switch (e.type) {
          case "conversation":
            setConvId(e.id);
            break;
          case "meta":
            setStatus(`${e.cls} → ${e.model}${e.advisor ? " +advisor" : ""}`);
            break;
          case "guard":
            if (Object.keys(e.findings).length) push("meta", `guard ${e.action}: ${Object.entries(e.findings).map(([k, v]) => `${k}×${v}`).join(" ")}`);
            break;
          case "approval":
            push("meta", `needs approval: ${e.reasons.join("; ")} — /approve, /edit <text>, /reject`);
            break;
          case "text":
            if (e.part === "revision" && !revising) {
              revising = true;
              if (acc) push("assistant", acc);
              acc = "";
              push("meta", "revised after cross-provider review:");
            }
            acc += e.delta;
            setLive(acc);
            break;
          case "tool":
            push("meta", `tool ${e.name}${e.detail ? `: ${e.detail}` : ""}`);
            break;
          case "failover":
            acc = "";
            setLive("");
            push("meta", `failover ${e.from}${e.to ? ` → ${e.to}` : ""}: ${e.why}`);
            break;
          case "advisor":
            push("meta", `advisor ${e.model}: ${e.verdict}${e.verdict === "issues" ? `\n${e.critique}` : ""}`);
            break;
          case "arena":
            lastArena.current = e;
            push("assistant", `── A: ${e.a.model}\n${e.a.text}\n\n── B: ${e.b.model}\n${e.b.text}\n\n/pick a or /pick b`);
            break;
          case "done":
            lastRun.current = e.runId;
            break;
          case "error":
            push("error", e.message);
            break;
        }
      }
    } catch (err: any) {
      if (!ac.signal.aborted) push("error", String(err.message ?? err));
    } finally {
      if (acc) push("assistant", acc);
      setLive("");
      setBusy(false);
      arenaNext.current = false;
    }
  }

  useInput((ch, key) => {
    if (picker) {
      if (key.upArrow) setPickIdx((i) => Math.max(0, i - 1));
      else if (key.downArrow) setPickIdx((i) => Math.min(picker.length - 1, i + 1));
      else if (key.return) {
        const id = picker[pickIdx].id;
        setPicker(null);
        resume(id);
      } else if (key.escape) setPicker(null);
      return;
    }
    if (key.ctrl && ch === "c") {
      if (busy) abort.current?.abort();
      else {
        exit();
        setTimeout(() => process.exit(0), 50);
      }
      return;
    }
    if (busy && !approval) return;
    const items = suggest(inputRef.current, commands());
    if (key.escape) return setInput("");
    if (items.length && (key.tab || key.upArrow || key.downArrow)) {
      const r = onMenuKey(key.tab ? "tab" : key.upArrow ? "up" : "down", inputRef.current, items, sel);
      if (r.input !== undefined) setInput(r.input);
      if (r.selected !== undefined) setSel(r.selected);
      return;
    }
    // Fast typing and pastes arrive as one chunk ("sage\r"), so newlines are handled inside chunks too.
    const chunk = key.return ? "\r" : ch;
    if (key.backspace || key.delete) return setInput((s) => s.slice(0, -1)), setSel(0);
    if (!chunk || key.ctrl || key.meta) return;
    const body = chunk.replace(/\r\n?/g, "\n");
    if (body.endsWith("\n") && !body.slice(0, -1).includes("\n")) {
      const t = inputRef.current + body.slice(0, -1);
      const r = onMenuKey("enter", t, suggest(t, commands()), sel);
      setSel(0);
      if (!r.submit) return setInput(r.input ?? t);
      setInput("");
      submit(r.input ?? t);
    } else {
      setInput((s) => s + body);
      setSel(0);
    }
  });

  const color = (k: Line["kind"]) => (k === "user" ? "cyan" : k === "error" ? "red" : k === "meta" || k === "note" ? "gray" : undefined);

  return (
    <>
      <Static items={done}>
        {(l) => (
          <Box key={l.key} marginBottom={l.kind === "assistant" ? 1 : 0}>
            <Text color={color(l.kind)}>{l.kind === "user" ? "› " : ""}{l.kind === "assistant" ? bold(l.text) : l.text}</Text>
          </Box>
        )}
      </Static>
      {live && <Text>{bold(live)}</Text>}
      {picker && (
        <Box flexDirection="column" borderStyle="round" paddingX={1}>
          <Text bold>Resume conversation (↑/↓, enter, esc)</Text>
          {picker.slice(0, 20).map((c, i) => (
            <Text key={c.id} inverse={i === pickIdx}>
              {new Date(c.updated).toLocaleString()}  {(c.last_model ?? "-").padEnd(24)} {c.title}
            </Text>
          ))}
        </Box>
      )}
      {approval && (
        <Box flexDirection="column" borderStyle="round" borderColor="yellow" paddingX={1}>
          <Text color="yellow">Approval needed: {approval.reasons.join("; ")}</Text>
          <Text>Will send: {approval.redacted.slice(0, 600)}</Text>
          <Text color="gray">/approve · /edit &lt;text&gt; · /reject</Text>
        </Box>
      )}
      <Box>
        <Text color="gray">
          [{model}{mode.mode === "agent" ? ` · agent ${mode.cwd}` : ""}{convId ? ` · ${convId}` : ""}] {busy ? `${status} …` : status}
        </Text>
      </Box>
      <Box>
        <Text color="cyan">› </Text>
        <Text>{input}</Text>
        <Text inverse> </Text>
      </Box>
      <SlashMenu items={suggest(input, commands())} selected={sel} />
    </>
  );
}

export async function runTui(opts: { resume?: string | true; model?: string }) {
  const { client } = await connect();
  render(<App client={client} initialResume={opts.resume} initialModel={opts.model} />, { exitOnCtrlC: false });
}
