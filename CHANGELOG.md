# Changelog

All notable changes to hib. Versions follow [semantic versioning](https://semver.org); before 1.0, a minor version can change behaviour.

## [0.5.0] - 2026-11-18

Guarded data for agents in sensitive work: command output, and trusted read-only MCP servers such as OIB's observability endpoint (shipped in OIB v1.3.0).

### Added
- **Trusted read-only MCP servers** (`[mcp.<name>]` in `config.toml`). hib's daemon calls the server for the agent; the agent never holds the bearer token. (#28)
  - Each server needs `read_only = true` and a `tools = [...]` list. A tool is offered only if it's on your list and the server marks it `readOnlyHint`. The optional `server = "<name>"` offers nothing if the server introduces itself under another name.
  - Calls run without prompts and are logged as `tool.permission` with `decided_by: "policy"` and `mcp_server`. Any other tool name is refused in the daemon. hib caps calls at 60 a minute per session and arguments at 16,000 characters.
  - Results are guarded with the session's placeholders: JSON value by value and part by part. Values under person, login and client-address keys (including OTLP attributes) become placeholders whole, while metric, span and service names and infrastructure ids stay readable. Only text parts are passed on, cut at 60,000 characters. Placeholders in arguments are swapped back to real values before the call.
  - `sensitive = true` also offers the server in sensitive folders. A server of the same name in your own Claude or Codex config is turned off in hib sessions.
  - Checked live against OIB's Grafana MCP and a staged Redis outage: the agent diagnosed it through `mcp__hib__oib__*` only, with no prompts, and neither the token nor the endpoint appeared in the event log.
- **Command output is guarded in sensitive folders.** Each command prints into a capture file of hib's. A PostToolUse hook, registered over Claude Code's control channel, gives the agent that output only after the guard. (#26)
  - Fails closed: if a command fails, is killed or times out, or the hook doesn't answer, the agent sees only the exit status. A session doesn't start without the hook.
  - Each command now runs in its own subshell, so `cd` and `export` don't carry over to the next one.
  - Checked on Linux; `bun test/manual/output-guard-probe.ts` rechecks it after a Claude Code upgrade.
- **`hib ask --workspace <dir> "prompt"`** runs one agent turn without the terminal UI, for scripts and acceptance tests such as OIB's `make ask`. (#32)
  - `[-m model] [--session id] [--json]`.
  - Anything that would ask you is denied and listed.
  - Exit codes: 0 done; 3 done, but something was denied; 1 error.

### Fixed
- **Later turns restore placeholders made during them.** From a session's second turn on, a placeholder first made by a Read copy or by command output wasn't turned back into the real value in that turn's answer. Two values could also get the same placeholder. (#27)
- **No false `protected.reverted` for an empty `.git/config.worktree`.** Claude Code's sandbox on Linux leaves one behind, and hib logged a critical revert after every turn. An empty one is now ignored; one with any content is still caught and put back. (#30)
- **Tests delete their temporary folders.** Each run used to leave thousands behind and could use up a tmpfs `/tmp`'s inodes. (#31)

## [0.4.0] - 2026-11-17

### Added
- **Session scopes** (Linux, opt-in: `[events] session_scope = true`). Each Claude or Codex CLI runs in a systemd user scope named after its session, `hib-<session_id>-<8 hex>.scope`, new each time the CLI starts. The unit name is on `session.start` as `scope`. Process telemetry such as Falco can then tie every process an agent starts to its session by cgroup, which survives `env -i`, `setsid` and a reordered environment. Checked live with Claude Code and Codex: shells, `sh -c` children, background jobs and `env -i setsid` stayed in the scope; a command inside the agent's OS sandbox couldn't start a scope of its own; killing the daemon ended the CLIs. `daemon.start` carries `session_scope` (`available` or `unavailable`). When systemd can't be reached, a `scope.unavailable` warning gives the reason and sessions run unscoped. Scopes aren't stopped at session end. (#24)

## [0.3.0] - 2026-11-17

SIEM noise and session tracing, from SIB's first rules running against hib.

### Changed
- **`home.changed` is a warning, not critical, when a CLI settings file changed only in preference keys** (`model`, `advisorModel`, `theme`, `tui`, `agentPushNotifEnabled` in Claude's `settings.json`, `model` and `model_reasoning_effort` in Codex's `config.toml`), as happens when you run `/model` or `/config` in another session. Such a change is marked `prefs_only: true`. Any other key (hooks, permissions, env, statusLine, MCP servers, `model_provider`), a mode change or a file that doesn't parse keeps it critical. (#20)
- **`HIB_SESSION` is passed as the first environment variable,** since Falco reads only the first 4 KB of a process's environment. Launchers (mise's wrappers) and bash can still reorder it, so treat it as best effort. Measured live, it sat at byte 1553 of 4602 in a Claude shell and 1477 of 1522 in a Codex shell, because hib passes the CLIs a minimal environment. (#22)

## [0.2.0] - 2026-11-16

Mostly the security event log and what a SIEM (such as [SIB](https://github.com/matijazezelj/sib)) needs to use it safely.

### Added
- **Event log profiles.** `[events] profile = "local"` (default: every field whole) or `"siem"` (for logs that leave the machine). `siem` hashes `workspace` and `account` with a keyed HMAC, cuts `net_host` and `url` to the registrable domain, logs only a program label instead of the command, and leaves out the peer address. Each setting (`workspace`, `account`, `net_host`, `command`, `remote`) can also be set on its own. (#11, #12)
- **`events.key_refused`.** If `~/.hib/events.key` is refused (a symlink, not a regular file, wrong owner, readable by others, wrong format), hib writes one warning per run giving only the reason. The key is also checked at daemon start. (#13)
- **`home.changed`.** Each agent turn checks shell startup files, Claude and Codex settings, instructions, hooks, agents, commands and skills (in `~/.claude`, `~/.codex` and every account's config folder), `~/.gitconfig`, ssh config, `authorized_keys` and `rc`, autostart entries and systemd user units. A change is reported in the timeline and as `home.changed`: critical, or a warning when every change was an edit you approved. These files are reported, never put back. (#14)
- **`HIB_SESSION`.** Agent CLIs start with `HIB_SESSION=<session_id>`, so every process an agent starts can be tied to its session by process telemetry such as Falco's `proc.env`. (#16)
- **A scripted agent for acceptance tests,** turned on only by `[testing] script_dir`. It replays tool calls through hib's real permission, data-rule, protected-file and home-watch checks, so an end-to-end test can trigger security events without a CLI login. A daemon running it says so in `daemon.start` (`script_driver: true`). (#15, #17)

### Changed
- **Domains** come from the Public Suffix List (`tldts`), ICANN suffixes only, so customer names under shared hosting suffixes don't leave the machine: `acme.s3.amazonaws.com` becomes `amazonaws.com`, and `you.github.io` becomes `github.io`. Hosts are read the way `new URL` reads them, so tricks like `https://evil.com\@good.com/` give the real host. IDN comes out as punycode. Link-local (`169.254.169.254`), CGNAT, unspecified, ULA and mapped IPv6 addresses are classed as internal. `.arpa`, `.corp` and `.local` names become `[INTERNAL]`, and input that can't be parsed becomes `[HOST]` or `[URL]`. (#12)
- **The program label** (`command = "program"`) splits the command the way the shell quotes it, so a word inside a quoted secret can't become the label. It knows more `sudo` and `env` options, and falls back to `[COMMAND]` when it can't tell safely. (#12)
- **`data.block`** carries only a fixed reason when commands are coarsened, never the file name or script path. (#12)

### Security
- The hash key is opened without following symlinks or blocking on a named pipe, and its size is capped. (#12)
- Redaction placeholders in a host field keep only their category; other bracketed text is treated as a name. (#12)

## 0.1.0 - 2026-11-15 (untagged)

First versioned release: the harness as built from 8 October to 15 November 2026.

- **The harness:** a local daemon over Claude Code and Codex subscriptions, with a router, failover, advisor and arena. It has terminal and browser UIs, workspace sessions with permission prompts, auto mode in an OS sandbox, background tasks in git worktrees, and an egress log.
- **Guard:** secrets, identifiers and configured terms are replaced with placeholders before anything leaves the machine, and restored in what comes back. Local name detection is optional.
- **Sensitive workspaces:** pinned to one account, every read asks, data files are read as pseudonymised copies, and there is no raw JSON or auto-memory.
- **Data analysis** without sending the data.
- **Protected files:** git hooks and config and agent config inside the workspace are checked after every turn, and unapproved changes are put back.
- **`hib pipe`** redacts log streams before they reach an LLM. (#7)
- **Security event log** (`~/.hib/events/events.jsonl`) for a SIEM, with a `daemon.alive` heartbeat and redaction hardened by fuzzing. (#8, #9)

[0.4.0]: https://github.com/matijazezelj/hib/releases/tag/v0.4.0
[0.3.0]: https://github.com/matijazezelj/hib/releases/tag/v0.3.0
[0.2.0]: https://github.com/matijazezelj/hib/releases/tag/v0.2.0
