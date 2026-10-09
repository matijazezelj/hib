# Progress

Where hib stands and what to do next. Agents working here: read this first, and update it when you finish a piece of work.
hib itself sends this file with the first message of every fresh workspace session.

_Last updated: 2026-10-09_

## Where it stands

hib is usable day to day: a local daemon, a terminal agent (`hib`), a web workspace (`hib serve`), a multi-model chat, and an
OpenAI-compatible router, all over the Claude Code and Codex subscription CLIs. CI runs typecheck and `bun test` (196 tests).

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
- **Auto mode** (`/auto`, off by default). Edits and commands run without asking, but risky commands (network, push, publish, sudo, rm -r, anything touching hib's daemon or credentials) still ask.
- **Advisor tool** (`/advisor`, off by default). hib's MCP server gives the agent an `advisor` tool backed by the other provider, through the guard, logged.
- **Web UI.** Dark-first redesign of chat, analyze, home and workspace. Slash commands in the web composer.
- **Terminal.** Ink terminal agent and router chat with slash autocomplete, and `**bold**` rendering.
- **Plugins.** Markdown plugins (skill, agent, route, guard, advisor) and code plugins pinned by SHA with trust.
- **PROGRESS.md.** Workspaces with this file at their root start every fresh session from it. In sensitive folders hib only points to it.

## Known issues
- **Auto mode is a speed bump, not a sandbox.** Any local process can get the daemon token (`~/.hib/token`, `/hib/session`), and a script the agent writes and runs can call the daemon. A real fix means sandboxing commands, e.g. Claude Code's Bash sandbox for Claude, or a per-session capability token instead of one daemon token.
- **`ls` came back empty in one auto-mode test** although the file existed. Command output display looks suspect; not investigated.
- **Advisor needs a logged-in account of the other provider.** Without one, `/advisor` switches itself off with a note.

## Next
1. **Background tasks.** `hib task "…"` / `/bg`: a session in its own git worktree, in auto mode, with a macOS notification when it's done or needs approval. `hib tasks` lists them, with review, merge and discard.
2. **Fix the auto-mode gap** above: a sandbox for agent commands, and/or a narrower token for the web UI.
3. **Look into the empty `ls` output** in workspace sessions.
4. **Before making the repo public:** add a LICENSE. Add a README line saying hib drives the official CLIs on your own subscriptions and never extracts their logins.

## How to check it works
- `bun test` and `bunx tsc --noEmit -p .`
- With a scratch home: `HIB_HOME=/tmp/hibhome hib daemon start`, then open the printed URL in a test folder.
- After changing web or daemon code, run `hib daemon stop`. The running daemon serves the old code.
