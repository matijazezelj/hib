# Progress

Where hib stands and what to do next. Agents working here: read this first, and update it when you finish a piece of work.
hib itself sends this file with the first message of every fresh workspace session.

_Last updated: 2026-10-09_

## Where it stands

hib is usable day to day: a local daemon, a terminal agent (`hib`), a web workspace (`hib serve`), a multi-model chat, and an
OpenAI-compatible router, all over the Claude Code and Codex subscription CLIs. CI runs typecheck and `bun test` (223 tests, 2 of them Linux-only).

### Done
- **Router.** OpenAI-compatible `/v1`. Classification uses rules first, then Haiku for anything ambiguous. Routes come from config with learned scores (Thompson sampling), and failover is driven by usage and rate limits. Also: advisor review on routes, arena, and work/personal accounts via `CLAUDE_CONFIG_DIR` / `CODEX_HOME`.
- **Guard.**
  - Detection: regex detectors ported from sib, plus local NER (optional).
  - Placeholders: secrets and identifiers become per-conversation `[HIB…]` placeholders, and the answer is restored as it streams.
  - Policy: ask-first, with an AES-GCM sealed vault.
  - Egress log of everything sent.
- **Workspaces.**
  - Agent sessions: long-lived native CLI sessions with permission prompts in the web UI and terminal, resume, and handoff across CLIs. The handoff transcript is guarded.
  - Shared daemon: CLI and web follow the same live session.
  - Browser panels: file tree, git panel, and a browser terminal.
- **Sensitive workspaces.**
  - Pinned to one account, with no handoff, failover, advisor or arena.
  - Secrets are blocked, and every read asks.
  - Data files reach the agent pseudonymised, and raw shell reads of data are blocked.
- **Analyze** (`hib analyze`, web panel). The model sees only the schema and writes `analyze(rows)`, which runs locally in a sandbox. Interpretation is optional. Includes column pseudonymisation and an offline GeoNames gazetteer for travel analysis.
- **Agent sandbox** (`src/workspace/sandbox.ts`). It's on in every session.
  - Claude runs with its Bash sandbox: `sandbox.enabled`, `failIfUnavailable`, `allowUnsandboxedCommands: false`, and `autoAllowBashIfSandboxed: false` so prompts still reach hib.
  - Codex runs with a `default_permissions` profile that extends `:workspace` and sets `filesystem = { path = "deny" }`. Without one there is nothing to confine a script the agent writes and runs.
  - Commands can't read `~/.hib`, CLI logins or credential stores, can't write outside the folder, and can't reach localhost (the daemon) or the network. A new host is a `SandboxNetworkAccess` prompt in Claude; Codex has no network.
  - Codex runs its own binary from `~/.codex/packages`, so only `auth.json` is denied there.
  - Nested Seatbelt isn't allowed (`sandbox_apply: Operation not permitted`), so hib can't wrap a whole CLI itself.
  - Checked end to end with real Claude and Codex sessions; the advisor MCP still reaches the daemon.
  - Git: Claude's sandbox lets the agent commit, including in task worktrees, but blocks the main repo's `.git/config` and `.git/hooks`. Codex keeps `.git` read-only by design, so a Codex agent can't commit; hib's own end-of-turn commit covers tasks.
  - Codex marks a request to run outside its sandbox only with a `reason` field. hib treats any request with one as "beyond the sandbox", which auto mode and "always" never approve. Approving one in Codex 0.160 still ran the command sandboxed.
  - Test sandbox probes with repos outside `/tmp`: Codex's workspace profile can write anywhere under `/tmp`, which skews results.
- **Browser login.** `/hib/session` sets the cookie only for a one-time code (15 min) that `POST /hib/login` mints with the token. `workspaceUrl()` mints one. Before, any local process could get the token from `/hib/session`.
- **Auto mode** (`/auto`, off by default; needs the sandbox). Edits and sandboxed commands run without asking. New network hosts ask, except package registries. Risky commands (push, publish, sudo, rm -r, anything naming hib's daemon or credentials) still ask. Without an OS sandbox (Linux without bwrap, Windows) auto mode and background tasks are refused.
- **Background tasks** (`hib task "…"`, `/bg` in the terminal and web).
  - Each task is one agent session in its own git worktree, on branch `hib/task-<id>`, in auto mode. Worktrees live in `~/.local/share/hib/worktrees` (override with `HIB_WORKTREES`). That path avoids `.hib`/`.claude`, which auto mode and the CLI deny rules treat as credentials.
  - The worktree is registered as a workspace so sessions, the guard and the web UI work there, but it's hidden from workspace listings.
  - The model is chosen for the original folder, so `accounts.dirs` pins still apply.
  - The agent gets a system note saying nobody is watching and that it should leave PROGRESS.md alone, so parallel tasks don't conflict on merge. Update PROGRESS.md after merging. hib commits whatever the agent leaves uncommitted at the end of each turn.
  - Status: running, waiting (a risky command or a guard approval), done, failed, or interrupted (the daemon restarted). A macOS notification fires on done, failed and needs-approval.
  - `hib tasks` lists them; `review`, `merge` (`--no-ff` into whatever the folder has checked out; a conflicting merge is aborted) and `discard` act on one, and `open` opens its session in the TUI. `/tasks` and `/task <id>` do the same on the web.
  - Off in sensitive workspaces, because a worktree outside the folder wouldn't inherit the pin. A task whose origin later becomes sensitive refuses new turns.
  - Code: `src/workspace/tasks.ts`, with tests in `test/tasks.test.ts`.
- **Advisor tool** (`/advisor`, off by default). hib's MCP server gives the agent an `advisor` tool backed by the other provider, through the guard, logged.
- **Web UI.** Dark-first redesign of chat, analyze, home and workspace. Slash commands in the web composer.
- **Terminal.** Ink terminal agent and router chat with slash autocomplete, and `**bold**` rendering.
- **Plugins.** Markdown plugins (skill, agent, route, guard, advisor) and code plugins pinned by SHA with trust.
- **PR #1 (merged).** Protected paths are judged on the resolved path, case-insensitively. Auto mode asks for WebFetch/WebSearch. "Always" for interpreters and wrappers (`python`, `node`, `bash`, `env`, `xargs`, `sudo`…) covers only the exact command line. Analysis code runs under bubblewrap on Linux.
- **PR #1 review follow-ups (2026-10-09).**
  - Race between check and use for protected files: every turn snapshots git hooks/config (the common dir too, for worktrees), `.claude/`, `.codex/`, `.hib/` and `.mcp.json` by content. Unapproved changes are put back, and a `protected_reverted` event reports them (`src/workspace/protect.ts`). Claude also gets `Edit(./.git/**)` as a deny rule; only `Edit(...)` rules are honoured, and they cover Write too.
  - `realTarget()` follows dangling symlinks, since a write through one creates its target. Tests cover dangling, nested and chained links, loops, paths that don't exist yet and a swapped hooks directory.
  - Web approvals carry `outbound` (host, full URL, prompt or query, guard findings, placeholder count), and both UIs show it.
    - Web calls get placeholders, not restored values, so a fetch can't leak what the guard redacted.
    - "Always" for WebFetch covers one host.
    - Claude always asks hib for WebFetch/WebSearch via an `ask` rule. Checked live: without it, the user's own settings or Claude's pre-approved sites let WebFetch run unasked.
  - Analysis on Linux: bubblewrap starts from an empty root with only `/usr`, `/lib*`, `/bin`, `/sbin`, bun and `src/analyze` mounted, read-only. All namespaces are unshared, and `/tmp` is empty.
  - README: approvals are a user-interaction safeguard; the OS sandbox is the boundary.
- **Ready to publish.** The repo has an MIT LICENSE, and the README says hib drives the official CLIs on your own subscriptions and never extracts their logins.
- **PROGRESS.md.** Workspaces with this file at their root start every fresh session from it. In sensitive folders hib only points to it.

## Known issues
- **Gaps in the sandbox.**
  - The macOS keychain is reachable from inside it, so a command can read a CLI login stored there (`security find-generic-password`). With the network closed it can only go back to the model's own vendor, or to a host you approve.
  - The CLIs' file tools (Read/Edit) aren't sandboxed; permission rules and hib's prompts hold them.
- **One daemon token.** The token is still all-powerful for anything outside an agent sandbox. Agents can't read it now, but a narrower per-client token would shrink it further.
- **`ls` came back empty in one auto-mode test** although the file existed. Command output display looks suspect; not investigated.
- **Advisor needs a logged-in account of the other provider.** Without one, `/advisor` switches itself off with a note.

## Next
1. **Left over from the PR #1 review.**
   - **Check the Linux analysis sandbox in CI.** The empty-root bubblewrap and its test that host files can't be seen are written but have only run on macOS, where they're skipped. CI now installs bwrap; confirm the Ubuntu job runs both Linux tests and passes.
   - **macOS analysis Seatbelt has the same shape.** It's `(allow default)` with only `$HOME` denied, so `/Volumes`, `/private/var`, `/private/tmp` and other users' folders stay readable. Invert it like bubblewrap, or at least deny those. Test it outside a sandboxed Claude session, since nested Seatbelt fails there.
   - **Codex web search isn't gated.** Codex runs `webSearch` items without asking, so hib only logs them.
2. **Review feedback, P1 items** (a security review on 2026-10-09; the P0s, agent isolation and daemon auth, are done above):
   - Sensitive workspaces: check that native CLI reads, subprocesses, hooks and MCP all respect the policy, now that the sandbox is there.
   - Prompt injection from repo content and tool results.
   - Where the regex/NER guard misses things.
   - (P2) Whether the router's learned scores get enough real feedback.
3. **Look into the empty `ls` output** in workspace sessions.
4. **Background task polish.**
   - A tasks panel in the web UI with review, merge and discard buttons. Today the web has only `/bg`, `/tasks` and `/task <id>`; review and merge need the CLI.
   - Worktrees start without `node_modules`, so the agent installs dependencies itself.
   - Tasks that branch from HEAD don't include the folder's uncommitted changes. hib warns about this.

## How to check it works
- `bun test` and `bunx tsc --noEmit -p .`
- With a scratch home: `HIB_HOME=/tmp/hibhome hib daemon start`, then open the printed URL in a test folder. Change `port` in its config.toml first if your own daemon is running.
- After changing web or daemon code, run `hib daemon stop`. The running daemon serves the old code.
