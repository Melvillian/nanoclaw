# Security Audit: NanoClaw

**Date:** 2026-02-14
**Auditor:** Claude Code (Opus 4.6)
**Scope:** Exhaustive audit of the NanoClaw codebase to validate three security claims

---

## The Three Claims Under Test

1. **"does not give access to sensitive data"**
2. **"does not process untrusted input without my explicit permission"**
3. **"only communicates externally through an authenticated MCP tool, or my explicit permission via web search"**

---

## CLAIM 1: "does not give access to sensitive data"

### INVALIDATED

**Finding 1.1 (HIGH) - API credentials are discoverable inside containers**

The agent runs with `permissionMode: 'bypassPermissions'` and `allowDangerouslySkipPermissions: true` (`container/agent-runner/src/index.ts:437-438`). Secrets are passed into the SDK environment at lines 512-514:

```typescript
const sdkEnv: Record<string, string | undefined> = { ...process.env };
for (const [key, value] of Object.entries(containerInput.secrets || {})) {
  sdkEnv[key] = value;
}
```

The `createSanitizeBashHook` (line 192-209) prepends `unset ANTHROPIC_API_KEY CLAUDE_CODE_OAUTH_TOKEN` to every Bash command, but this is bypassable:
- The agent can use the `Read` tool on `/proc/self/environ` or `/proc/1/environ`
- The agent can use `ToolSearch` to find and use tools that expose environment state
- The credentials must exist in the process for the SDK to authenticate -- there's no way to hide them from an agent with full tool access

This is already acknowledged in `docs/SECURITY.md:79` but still invalidates the claim.

**Finding 1.2 (HIGH) - Main group container can read `.env` file directly**

The main group gets the entire project root mounted at `/workspace/project` (`container-runner.ts:68-73`). The `.env` file sits at the project root and contains `ANTHROPIC_API_KEY` and `CLAUDE_CODE_OAUTH_TOKEN`. The mount security blocked patterns (`.env` is in `DEFAULT_BLOCKED_PATTERNS`) are only enforced for **additional mounts** validated by `validateAdditionalMounts`, NOT for the hardcoded primary mounts.  

So the main group agent can simply: `Read /workspace/project/.env` to get all secrets.

**Finding 1.3 (MEDIUM) - Message content stored unencrypted in SQLite**

All messages for registered groups are stored as plaintext in `store/messages.db` (`db.ts:196-207`). This includes message content, sender identity, and timestamps. The main group mounts the entire project root, so it can read `store/messages.db` directly and see messages from ALL registered groups, breaking cross-group isolation.

**Finding 1.4 (LOW) - Container logs may contain sensitive prompts**

On error or in verbose mode, full container input (including the user's prompt) is written to `groups/{folder}/logs/` (`container-runner.ts:467-488`). Secrets are deleted from the input object before logging (line 294), but the prompt content itself (which may contain sensitive user messages) is preserved.

---

## CLAIM 2: "does not process untrusted input without explicit permission"

### GENERALLY VALID, with caveats

**Supports the claim:**
- Groups must be explicitly registered before messages are processed (`index.ts:166` -- `if (groups[chatJid])`)
- Non-main groups require a trigger pattern match (`@Andy`) before the agent is invoked (`index.ts:136-141`)
- The main group is the user's private self-chat -- only the user can send messages there
- IPC authorization prevents non-main groups from sending messages to other chats or registering new groups (`ipc.ts:78-94`, `356-361`)

**Caveats that weaken the claim:**

**Finding 2.1 (MEDIUM) - No validation on `folder` parameter in `register_group`**

When the main group agent calls `register_group`, the `folder` field is passed through without any validation (`ipc-mcp-stdio.ts:249`, `ipc.ts:366`). The Zod schema only validates it's a string. A path traversal value like `../../etc` would:
- Create directories outside `groups/` (`index.ts:84`)
- Mount unintended host directories into the container (`container-runner.ts:77`)

This requires a prompt injection in the main group, but the lack of input validation is a defense-in-depth gap. The `containerName` sanitization at line 247 (`replace(/[^a-zA-Z0-9-]/g, '-')`) prevents command injection in shell calls, but the unsanitized path is used for filesystem operations and mounts.

**Finding 2.2 (MEDIUM) - Scheduled tasks run automatically without per-execution consent**

Once the agent creates a scheduled task via the `schedule_task` MCP tool, it runs automatically on schedule (`task-scheduler.ts:197-208`). The user gave implicit permission by triggering the agent that created the task, but each subsequent execution proceeds without consent. A prompt injection could create tasks that persist and execute indefinitely.

**Finding 2.3 (LOW) - Agent has unrestricted tool access within container**

The `permissionMode: 'bypassPermissions'` setting means the agent never asks for confirmation before using tools (Bash, Read, Write, WebSearch, etc.). Within the container sandbox, every operation proceeds automatically. This is by design (the container IS the security boundary), but it means any prompt injection that activates the agent gets full autonomous execution.

---

## CLAIM 3: "only communicates externally through an authenticated MCP tool, or explicit permission via web search"

### INVALIDATED

**Finding 3.1 (CRITICAL) - Agent has unrestricted network access via Bash**

The container has full network access (confirmed in `docs/SECURITY.md:89`: "Network access: Unrestricted" and `docs/APPLE-CONTAINER-NETWORKING.md` which documents the NAT setup). The agent's `allowedTools` include `Bash` (`container/agent-runner/src/index.ts:427`), and `permissionMode: 'bypassPermissions'` means no confirmation is required.

The agent can run:
- `curl https://anywhere.com` -- arbitrary HTTP requests
- `wget`, `nc`, `ssh`, or any network tool installed in the container
- The Dockerfile installs `curl` and `git` (`container/Dockerfile:24-25`)

None of these go through an authenticated MCP tool.

**Finding 3.2 (HIGH) - `WebFetch` tool allows unauthenticated external requests**

`WebFetch` is in the allowed tools list (`index.ts:429`). It fetches arbitrary URLs without requiring authentication to any MCP server. It's a Claude Code built-in tool, not a NanoClaw MCP tool.

**Finding 3.3 (HIGH) - Browser automation enables unrestricted web access**

The container has Chromium installed (`Dockerfile:8`) and the `agent-browser` skill (`container/skills/agent-browser/SKILL.md`) enables browser automation. The agent can navigate to any website, fill forms, and interact with web services.

**Finding 3.4 (MEDIUM) - WhatsApp communication bypasses MCP**

The host process sends WhatsApp messages directly via the Baileys library (`channels/whatsapp.ts:197`). While the agent triggers this through the `send_message` MCP tool, the actual external communication (WhatsApp WebSocket) is a direct library call, not an authenticated MCP tool.

**Summary of external communication channels NOT going through authenticated MCP:**

| Channel | Mechanism | Auth Required | MCP? |
|---------|-----------|---------------|------|
| Anthropic API | Claude Agent SDK | API key | No |
| WhatsApp | Baileys WebSocket | WA session | No |
| Arbitrary HTTP | Bash (`curl`) | None | No |
| Web browsing | Chromium/agent-browser | None | No |
| `WebFetch` | Claude built-in tool | None | No |
| `WebSearch` | Claude built-in tool | None | No (but user mentioned this) |
| `git push` / `git clone` | Bash | Optional | No |

---

## Recommended Fixes

### For Claim 1 (sensitive data):
1. **Block `.env` access in main group mount** -- add a `.dockerignore`-style exclusion or mount the project root with `.env` explicitly excluded
2. **Block `store/` access from main group** -- the database contains cross-group messages

### For Claim 2 (untrusted input):
3. **Validate `folder` parameter** -- enforce `^[a-z0-9-]+$` regex and reject reserved names (`main`, `global`, `ipc`, `sessions`, `errors`)

### For Claim 3 (external communication):
4. **Restrict container networking** -- Apple Container likely supports network policies; restrict egress to only Anthropic API endpoints
5. **Remove `Bash` from `allowedTools`** or configure the container without network tools (`curl`, `git`)
6. **Remove `WebFetch` from `allowedTools`** if it's not intended to be available
7. **If only MCP-authenticated communication is desired**, the allowed tools list should be reduced to: `Read`, `Write`, `Edit`, `Glob`, `Grep`, `Task`, `TaskOutput`, `ToolSearch`, `mcp__nanoclaw__*`

---

## What IS Working Well

- Container isolation via Apple Container is solid -- the primary security boundary
- Mount security with external allowlist is well-designed and tamper-proof from agents
- IPC authorization correctly prevents cross-group privilege escalation
- Credential filtering only allows 2 specific env vars
- Secret deletion from logs prevents accidental logging
- WhatsApp auth state is never mounted into containers
- All SQL queries use parameterized statements (no SQL injection)
- The `containerName` regex sanitization prevents shell injection
- The `osascript` notification uses a hardcoded string (no injection)
- The `escapeXml` function in `router.ts` properly escapes the 4 critical XML entities
