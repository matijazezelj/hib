# Design: MCP results and command output in sensitive folders

Status: (b) command output is implemented (2026-11-17), through a hook rather than the FIFOs recommended below; see
"(b) as built". (a) is implemented (2026-11-18) for streamable-HTTP servers declared in config.toml; see "(a) as built". Written 2026-10-20 after an end-to-end SIEM test.

In a sensitive folder, hib guards what the agent reads through Read (a pseudonymised copy) and what you type. Two
channels still go out unguarded or can't be used at all:
- **MCP servers.** `--strict-mcp-config` turns off every server but hib's own, so a SIEM MCP server can't be used. Outside
  sensitive folders, MCP results aren't guarded.
- **Command output.** hib asks before each Bash command, then sends whatever it prints (ssh queries, `gh`, script
  summaries). This is the largest remaining source of leaks.

Both need the session's vault, the same one that made the tokens the agent already has. Otherwise `jdoe` in an MCP
result gets a different token from `[…-USER-NAME-3]` in the Read copy, and the model can't connect them. The vault lives
in the daemon (`Live.vault`, sealed at rest). The agent's sandbox can't reach the daemon or `~/.hib`, and that's deliberate.

## (a) An allow-listed MCP proxy

**Where it runs.** Claude Code starts MCP servers itself, outside the Bash sandbox. That's how `advisor-mcp.ts` already
reaches the daemon with a per-session key (`HIB_ADVISOR_KEY`) that can do one thing. The proxy follows the same pattern:
- `hib-mcp` is a stdio shim with no credentials. It holds a per-session key scoped to `mcp`, and relays JSON-RPC to the
  daemon (`POST /ws/mcp`).
- The daemon starts the real servers. They come from a per-folder allow-list in the workspace policy, set at the terminal
  only, like `keep`: `hib workspace mcp allow siem -- npx @acme/siem-mcp`. The servers' own credentials (SIEM API keys)
  never enter the agent's process tree.
- `--strict-mcp-config` stays. The only server Claude sees is `hib`, which lists the allowed servers' tools under a prefix
  (`siem__search`).

**A call.**
1. Claude asks permission for `mcp__hib__siem__search`. hib shows the approval with the arguments restored. "Always" is
   keyed on the exact call, as for any MCP tool today.
2. The daemon restores tokens in the arguments with `restoreDeep(args, l.vault)`, so `user: "[…-USER-NAME-3]"` queries the
   real user. This half already exists for tool inputs in `allowDecision`.
3. The upstream server's result is guarded with the session vault before it reaches the shim:
   - JSON content that holds records (a search hit list) goes through the same path as a Read copy: `loadTable`'s record
     finding and flattening, `columnsToHide` (with the folder's keep-list), `pseudonymize`, then the regex guard per cell.
   - Other text gets `obfuscateText`, plus every value already in the vault (the `replaceKnown` step). A name tokenised
     from a Read copy then gets the same token in an MCP result.
   - Encoded payloads, JSON in strings and name detection come along automatically, since it's the same guard.
4. Egress records the call, the guarded result and the columns hidden, as for a Read copy.

**Trade-offs.**
- The daemon now runs third-party server code. It runs as a child of the daemon, outside the agent sandbox, like any MCP
  server you add to Claude Code. The allow-list and the terminal-only setting are the control, the same trust step as
  `hib plugin trust`. A later step could start these servers under the analyze sandbox profile, with network allowed
  only to the configured hosts.
- Results that aren't JSON or text (images, resources) are refused at first, not passed through.
- Restoring arguments means the model can make the server look up any value it has a token for. That's the point, and
  each call is approved.

## (a) as built (2026-11-18)

Built for OIB's read-only Grafana MCP (mcp-grafana, `--disable-write`, streamable HTTP with a bearer token). Differences
from the proposal above:
- **Declared in `~/.hib/config.toml`** (`[mcp.<name>]`: url, token_file + token_key or token_env, `read_only = true`,
  `sensitive`, optional `tools` globs), not a per-folder allow-list. Only streamable HTTP; the daemon doesn't start
  server processes, so it runs no third-party code.
- **No prompts.** A tool is offered only if the config says `read_only = true`, the server marks it `readOnlyHint`, and
  it matches `tools`. Those calls are allowed by policy (`tool.permission`, `decided_by: "policy"`, `mcp_server`);
  anything else is refused in the daemon, whatever the CLI allowed. The proposal approved each call.
- **The shim** is `hib-mcp.ts` (the advisor's server, generalised): `HIB_MCP_KEY` lets it call `POST /ws/mcp`
  (`tools/list`, `tools/call`) for its session only. The token is read by the daemon; the shim, the CLI's environment
  and arguments and the event log never see it.
- **Results** are guarded value by value when they're JSON (decoded, so escapes don't hide a value; a value under an
  identifying key becomes a token whole, by the Read copies' column-name rules), otherwise like a `.log` Read copy.
  Paths and machine names are guarded (`keepPaths` off). Known vault values get their tokens. The agent gets 60,000
  characters at most; name detection only covers that. The table path (`loadTable`/`columnsToHide`) isn't used: it
  would turn Loki streams into CSV and needs records of one shape.
- **The CLI's own server of the same name** is denied (Claude: `mcp__<name>` deny rule) or switched off (Codex:
  `mcp_servers.<name>.enabled=false`, only when its config defines it, since Codex refuses an entry with no transport).
- Fixed along the way: from the second turn on, a turn used a vault freshly loaded from the database while Read copies,
  command output and MCP results added tokens to the live session's vault, so a token first minted in a later turn
  didn't restore in the answer (and the two could mint the same token for different values). The turn now uses the
  live vault.

## (b) Guarding Bash output in sensitive sessions

hib already sees every command before it runs (`can_use_tool`), and `allowDecision` can return `updatedInput`, so it can
rewrite the command. The open question is where the filter runs and how it reaches the vault.

| Option | How | For | Against |
|---|---|---|---|
| 1. Unix socket into the sandbox | Allow one socket (`sandbox.network.allowUnixSockets`). The rewrite is `{ cmd; } 2>&1 \| hib-filter`; the filter sends output to the daemon and prints what comes back. | Simple; streams. | Opens a channel from the sandbox to the daemon. Any sandboxed code can use it: as an oracle (send a guess, see whether it comes back as a known token), to grow the vault, or to attack the endpoint. Needs a separate socket listener and an auth story. |
| 2. Socket plus a one-shot capability | As 1, but the rewrite carries a random token valid for this call's output only. | Limits use to the approved command's lifetime. | The socket and oracle risk stay while the command runs, and the token is visible to the command it's meant to constrain. |
| 3. Filter outside the sandbox, through FIFOs | hib makes two FIFOs per call in a private directory and adds it to the sandbox's write/read allow-list. The rewrite is `{ cmd\n} > in.fifo 2>&1; echo "[exit $?]" >> in.fifo; cat out.fifo`. The daemon (outside the sandbox) reads `in.fifo`, guards it with the session vault, and writes `out.fifo`. | No path from the sandbox to the daemon or the vault. The sandbox gains only two FIFOs, and the only thing it can get back is guarded output. Works with the same guard as (a), including known-value replacement. | Output only reaches the model in guarded chunks (per line, or whole at the end). It's more involved: deadlines, cleanup on timeout or kill, a command that never closes stdout. hib must also know the sandbox honours a per-session write allow-list (check with `sandbox-probe.ts`). |
| 4. A PostToolUse hook | Claude Code runs hooks outside the sandbox. A hib hook would rewrite the Bash tool result. | No change to the command. | Claude Code documents output replacement for MCP tools; whether a hook can replace Bash output is unverified, and it could change between releases. hib passes `--setting-sources user`, so it would have to inject the hook via `--settings`. |
| 5. Don't send output | Approve commands, but return only exit status and line counts. | Trivially safe. | Breaks most investigative use (`ssh … grep`, `gh`). |

**Recommendation: option 3.**
- It's the only one that keeps today's invariant: nothing inside the sandbox can reach hib's home, the daemon or the vault.
- The FIFOs carry raw output out and guarded output back, nothing else.
- A command that writes elsewhere (a file in the folder) is already covered: reading that file back goes through Read, which asks.

Details to settle when building it:
- **Bypasses.** A command can still bypass the pipe only by not printing: writing a file, which Read guards, or reaching
  the network, which the sandbox closes. Background jobs inherit the redirected descriptors, so their output is guarded
  too. hib reads `in.fifo` until EOF or the tool's timeout. After the timeout it writes what it has, guarded, and a note.
- **Granularity.** Guard line by line, with a small lookahead so an encoded blob or PEM block that spans lines is judged
  whole. Run name detection within the same budget as prompts, falling back to tokenising free-text lines.
- **What it applies to.** Every approved Bash command in a sensitive session. "Always" rules still produce the rewrite;
  the rewrite is not optional.
- **Proving it.** Add a probe to `sandbox-probe.ts`: a sandboxed command can't open the daemon port, the socket or
  `~/.hib`, but can write `in.fifo` and read `out.fifo`. The test: a command that prints a known user's email must come
  back with the session's token.

Option 4 is worth re-checking against each Claude Code release. If hooks can replace Bash output, they'd be a simpler
carrier for the same daemon-side guard, with no changes to the sandbox.

## (b) as built (2026-11-17)

Option 4 was re-checked against Claude Code 2.1.326 and holds: a PostToolUse hook can replace a built-in tool's output
(`hookSpecificOutput.updatedToolOutput`, documented for Bash), and a host can register hooks over the stream-json control
channel (`initialize` with `hooks`; the CLI calls back with `hook_callback`; the reply reports `hooks_applied`). So the
guard runs in the daemon with the session vault, and nothing in the sandbox can reach it. The hook alone fails open,
though: a failing command goes to PostToolUseFailure, which can't rewrite; a hook that times out or returns a shape the
CLI rejects passes the original on; a command killed with its shell never reaches the hook. So it's combined with the
capture idea from option 3:
- Every allowed Bash call is rewritten (`wrapCommand`) to `( eval '<cmd>' ) > <capture>/<tool_use_id> 2>&1`, then
  `printf '[exit %s]'`. As one quoted string, a `)` in the command can't close the subshell and print past the redirect. The tool's own output is only the exit status, and the subshell keeps `exit 3` from failing the
  tool. Whatever the hook does or doesn't do, the model and Claude's transcript never get the raw text.
- hib creates the capture file before the command runs (`makeCapture`, O_EXCL) and pins its device and inode. The hook
  reads only that file (no symlinks, a regular file with one link owned by the user, capped, cut at a line break), so a
  data file renamed onto the path is refused. It guards it with
  the session's vault (`guardOutput`: the standard guard, name detection, `Vault.knownFindings` for values already
  tokenized) and returns it as `stdout`.
- The capture folder is the only extra path the sandbox may write (`filesystem.allowWrite`). Read rules deny it to the
  file tools; a command reading it prints into its own capture file, so that comes back guarded too. `Monitor` is denied
  and `run_in_background` forced off; a command that outlives its timeout keeps its capture file.
- Without `hooks_applied: true` the session doesn't start.
- Checked live on Linux: plain, failing (exit 3), killed (`kill -9 $$`), `)`-escape and subagent commands, and Read/Grep
  of a file left in the capture folder; the marker never reached the model or the transcript. macOS is unchecked.
- Commands no longer share a shell: `cd` and exports don't carry over (the agent is told, in the sensitive-folder note). `test/manual/output-guard-probe.ts` repeats this for each Claude Code release, since the control
  channel isn't a documented interface.

Not covered: a command that writes to its parent shell's own output (`/proc/$PPID/fd/1`) puts text in the tool result;
the hook guards that too, but if that command also kills its shell, it goes out unguarded. That takes a command written
to get around the guard, not an accident.
