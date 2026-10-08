import type { ServerWebSocket } from "bun";

export interface TermData {
  kind: "terminal";
  cwd: string;
  proc?: ReturnType<typeof Bun.spawn>;
}

/** A login shell on a native pty, bridged to a WebSocket. Client sends raw input, or JSON {resize:[cols,rows]}. */
export const terminalSocket = {
  open(ws: ServerWebSocket<TermData>) {
    const shell = process.env.SHELL || "/bin/zsh";
    const proc = Bun.spawn([shell, "-l"], {
      cwd: ws.data.cwd,
      env: { ...process.env, TERM: "xterm-256color" },
      terminal: {
        cols: 100,
        rows: 30,
        data(_t: unknown, d: Uint8Array) {
          ws.sendBinary(d);
        },
      },
    } as any);
    ws.data.proc = proc;
    proc.exited.then(() => ws.close());
  },
  message(ws: ServerWebSocket<TermData>, msg: string | Buffer) {
    const term = (ws.data.proc as any)?.terminal;
    if (!term) return;
    const s = typeof msg === "string" ? msg : msg.toString();
    if (s.startsWith("{\"resize\"")) {
      try {
        const [cols, rows] = JSON.parse(s).resize;
        term.resize(cols, rows);
        return;
      } catch {}
    }
    term.write(s);
  },
  close(ws: ServerWebSocket<TermData>) {
    ws.data.proc?.kill();
  },
};
