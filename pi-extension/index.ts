import { createHash, randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import {
    createBashTool,
    createEditTool,
    createFindTool,
    createGrepTool,
    createLsTool,
    createReadTool,
    createWriteTool,
} from "@earendil-works/pi-coding-agent";

type FsMode = "readonly" | "write" | "unrestricted";
type NetMode = "none" | "unrestricted" | "restricted";
type ApprovalChoice = "allow once" | "allow for session" | "always allow" | "deny";
type ApprovalDecision = "allow_once" | "allow_for_session" | "always_allow" | "deny";

type SandboxState = {
    fs: FsMode;
    net: NetMode;
    sessionKey: string;
    outerSandbox: boolean;
    projectSandboxTrusted: boolean;
};

type ApprovalRequestFrame = {
    type: "approval_request";
    id: string;
    host: string;
    protocol: string;
    port: number;
};

type ResultFrame = {
    type: "result";
    value: any;
};

type PendingApprovalUiState = {
    id: string;
    host: string;
    protocol: string;
    port: number;
    status: "pending" | "responded";
};

type QueuedApprovalPrompt = {
    id: string;
    request: ApprovalRequestFrame;
    ctx: ExtensionContext;
    sendDecision: (choice: ApprovalChoice) => void;
};

type ApprovalEventPayload = {
    id: string;
    toolName: string;
    host: string;
    protocol: string;
    port: number;
    fs: FsMode;
    net: NetMode;
    sessionKey: string;
    decision?: ApprovalChoice;
};

const READ_ONLY_TOOLS = new Set(["read", "grep", "find", "ls"]);
const PI_SANDBOX_BIN = process.env.PI_SANDBOX_BIN || "pi-sandbox";
const pendingApprovals = new Map<string, PendingApprovalUiState>();
const approvalPromptQueue: QueuedApprovalPrompt[] = [];
let approvalPromptDrain: Promise<void> | null = null;

async function readJson(path: string): Promise<any | null> {
    try {
        return JSON.parse(await readFile(path, "utf8"));
    } catch {
        return null;
    }
}

async function loadConfigDefaults(cwd: string, allowProject: boolean): Promise<{ fs?: FsMode; net?: NetMode }> {
    const user = ((await readJson(join(homedir(), ".pi", "agent", "settings.json"))) || {})?.ZeePal?.sandbox || {};
    if (!allowProject) {
        return {
            fs: user?.fs ?? undefined,
            net: user?.net ?? undefined,
        };
    }

    const project = ((await readJson(join(cwd, ".pi", "settings.json"))) || {})?.ZeePal?.sandbox || {};
    return {
        fs: project?.fs ?? user?.fs ?? undefined,
        net: project?.net ?? user?.net ?? undefined,
    };
}

function deriveSessionKey(ctx: ExtensionContext): string {
    const sessionFile = ctx.sessionManager.getSessionFile();
    if (!sessionFile) return randomUUID();
    return createHash("sha256").update(sessionFile).digest("hex").slice(0, 24);
}

function deriveDefaultFs(pi: ExtensionAPI): FsMode {
    const active = pi.getActiveTools();
    if (active.length > 0 && active.every((name) => READ_ONLY_TOOLS.has(name))) {
        return "readonly";
    }
    return "write";
}

function directPassthroughMode(state: SandboxState): boolean {
    return state.fs === "unrestricted" && state.net === "unrestricted";
}

function networkFooterLabel(state: SandboxState): string {
    if (state.net === "none") return "none";
    if (state.net === "restricted") return "restricted";
    return state.outerSandbox ? "sandboxed" : "unrestricted";
}

function pendingApprovalCount(): number {
    let count = 0;
    for (const approval of pendingApprovals.values()) {
        if (approval.status === "pending") count += 1;
    }
    return count;
}

function footerLabel(state: SandboxState): string {
    const base = `${state.fs} ${networkFooterLabel(state)}`;
    const pending = pendingApprovalCount();
    return pending > 0 ? `${base} approvals:${pending}` : base;
}

function updateStatus(ctx: ExtensionContext, state: SandboxState) {
    ctx.ui.setStatus("pi-sandbox", footerLabel(state));
}

function sandboxEnv(state: SandboxState): NodeJS.ProcessEnv {
    return {
        ...process.env,
        PI_SANDBOX_PROJECT_SETTINGS_TRUSTED: state.projectSandboxTrusted ? "1" : "0",
    };
}

function toolArgs(toolName: string, ctx: ExtensionContext, state: SandboxState): string[] {
    return [
        "tool",
        toolName,
        "--fs",
        state.fs,
        "--net",
        state.net,
        "--cwd",
        ctx.cwd,
        "--session",
        state.sessionKey,
        "--approval",
        "external",
    ];
}

async function promptApproval(
    ctx: ExtensionContext,
    request: ApprovalRequestFrame,
): Promise<ApprovalChoice> {
    if (!ctx.hasUI) return "deny";
    const queued = pendingApprovalCount();
    const suffix = queued > 1 ? ` (${queued} queued)` : "";
    const choice = await ctx.ui.select(
        `Network access requested${suffix}: ${request.host}:${request.port} (${request.protocol})`,
        [
            "allow once",
            "allow for session",
            "always allow",
            "deny",
        ],
    );
    return (choice as ApprovalChoice) || "deny";
}

function approvalChoiceToDecision(choice: ApprovalChoice): ApprovalDecision {
    switch (choice) {
        case "allow once":
            return "allow_once";
        case "allow for session":
            return "allow_for_session";
        case "always allow":
            return "always_allow";
        case "deny":
        default:
            return "deny";
    }
}

function assertSandboxSuccess(result: any): void {
    if (result?.ok !== false) return;
    const message = result?.error?.message || result?.text || "pi-sandbox tool failed";
    throw new Error(String(message));
}

function makeReadResult(result: any) {
    assertSandboxSuccess(result);
    return {
        content: [{ type: "text", text: result.text }],
        details: result.truncated
            ? {
                truncation: {
                    truncated: true,
                    totalLines: result.lineCount,
                    outputLines: String(result.text || "").split("\n").length,
                },
            }
            : undefined,
    };
}

function makeTextResult(result: any) {
    assertSandboxSuccess(result);
    return {
        content: [{ type: "text", text: result.text }],
        details: result.truncated ? { truncation: { truncated: true } } : undefined,
    };
}

function combineBashOutput(result: any): string {
    const parts = [result.stdout || "", result.stderr || ""].filter((part) => part && part.length > 0);
    return parts.join(parts.length > 1 ? "\n" : "") || "(no output)";
}

export default function (pi: ExtensionAPI) {
    const cwd = process.cwd();
    const originals = {
        read: createReadTool(cwd),
        write: createWriteTool(cwd),
        edit: createEditTool(cwd),
        ls: createLsTool(cwd),
        find: createFindTool(cwd),
        grep: createGrepTool(cwd),
        bash: createBashTool(cwd),
    };

    const state: SandboxState = {
        fs: "write",
        net: "none",
        sessionKey: randomUUID(),
        outerSandbox: process.env.AGENTWRAP_SANDBOX === "true",
        projectSandboxTrusted: false,
    };

    function approvalEventPayload(
        toolName: string,
        request: ApprovalRequestFrame,
        decision?: ApprovalChoice,
    ): ApprovalEventPayload {
        return {
            id: request.id,
            toolName,
            host: request.host,
            protocol: request.protocol,
            port: request.port,
            fs: state.fs,
            net: state.net,
            sessionKey: state.sessionKey,
            decision,
        };
    }

    function dropQueuedApprovalPrompts(ids: Iterable<string>) {
        const idSet = new Set(ids);
        for (let i = approvalPromptQueue.length - 1; i >= 0; i -= 1) {
            if (idSet.has(approvalPromptQueue[i].id)) {
                approvalPromptQueue.splice(i, 1);
            }
        }
    }

    function ensureApprovalPromptDrain() {
        if (approvalPromptDrain) return;
        approvalPromptDrain = (async () => {
            while (approvalPromptQueue.length > 0) {
                const next = approvalPromptQueue.shift();
                if (!next) continue;
                const pending = pendingApprovals.get(next.id);
                if (!pending || pending.status !== "pending") continue;
                let choice: ApprovalChoice = "deny";
                try {
                    choice = await promptApproval(next.ctx, next.request);
                } catch {
                    choice = "deny";
                }
                next.sendDecision(choice);
            }
        })().finally(() => {
            approvalPromptDrain = null;
            if (approvalPromptQueue.length > 0) {
                ensureApprovalPromptDrain();
            }
        });
    }

    function enqueueApprovalPrompt(item: QueuedApprovalPrompt) {
        approvalPromptQueue.push(item);
        ensureApprovalPromptDrain();
    }

    async function resolveToolCall(toolName: string, params: any, ctx: ExtensionContext, signal?: AbortSignal): Promise<any> {
        return new Promise((resolve, reject) => {
            const child = spawn(PI_SANDBOX_BIN, toolArgs(toolName, ctx, state), {
                stdio: ["pipe", "pipe", "pipe"],
                env: sandboxEnv(state),
            });
            const stderr: Buffer[] = [];
            const localApprovalIds = new Set<string>();
            let settled = false;
            let resultSeen = false;

            const cleanupLocalApprovals = () => {
                for (const id of localApprovalIds) {
                    pendingApprovals.delete(id);
                }
                dropQueuedApprovalPrompts(localApprovalIds);
                updateStatus(ctx, state);
            };

            const fail = (error: Error) => {
                if (settled) return;
                settled = true;
                try {
                    child.kill("SIGTERM");
                } catch {
                    // ignore
                }
                cleanupLocalApprovals();
                reject(error);
            };

            const succeed = (value: any) => {
                if (settled) return;
                settled = true;
                cleanupLocalApprovals();
                resolve(value);
            };

            const writeFrame = (frame: any) => {
                if (child.stdin.destroyed || !child.stdin.writable) return;
                child.stdin.write(`${JSON.stringify(frame)}\n`);
            };

            const handleApprovalRequest = (frame: ApprovalRequestFrame) => {
                if (settled) return;
                if (pendingApprovals.has(frame.id)) return;

                localApprovalIds.add(frame.id);
                pendingApprovals.set(frame.id, {
                    id: frame.id,
                    host: frame.host,
                    protocol: frame.protocol,
                    port: frame.port,
                    status: "pending",
                });
                updateStatus(ctx, state);
                pi.events.emit("pi-sandbox:approval-required", approvalEventPayload(toolName, frame));

                enqueueApprovalPrompt({
                    id: frame.id,
                    request: frame,
                    ctx,
                    sendDecision: (choice) => {
                        const pending = pendingApprovals.get(frame.id);
                        if (!pending || pending.status !== "pending" || settled) return;
                        pending.status = "responded";
                        pendingApprovals.set(frame.id, pending);
                        updateStatus(ctx, state);
                        pi.events.emit("pi-sandbox:approval-resolved", approvalEventPayload(toolName, frame, choice));
                        writeFrame({
                            type: "approval_response",
                            id: frame.id,
                            decision: approvalChoiceToDecision(choice),
                        });
                    },
                });
            };

            const handleFrame = (line: string) => {
                let frame: ApprovalRequestFrame | ResultFrame;
                try {
                    frame = JSON.parse(line);
                } catch (error) {
                    fail(new Error(`pi-sandbox emitted invalid JSONL: ${String(error)}`));
                    return;
                }

                if (frame?.type === "approval_request") {
                    handleApprovalRequest(frame as ApprovalRequestFrame);
                    return;
                }

                if (frame?.type === "result") {
                    resultSeen = true;
                    try {
                        child.stdin.end();
                    } catch {
                        // ignore
                    }
                    succeed((frame as ResultFrame).value);
                    return;
                }

                fail(new Error(`pi-sandbox emitted unexpected frame: ${line}`));
            };

            child.stderr.on("data", (chunk) => stderr.push(Buffer.from(chunk)));
            child.on("error", (error) => fail(error as Error));

            const stdoutLines = createInterface({ input: child.stdout, crlfDelay: Infinity });
            stdoutLines.on("line", handleFrame);

            const onAbort = () => {
                if (!settled) {
                    try {
                        child.kill("SIGTERM");
                    } catch {
                        // ignore
                    }
                }
            };
            signal?.addEventListener("abort", onAbort, { once: true });

            child.on("close", (code) => {
                signal?.removeEventListener("abort", onAbort);
                stdoutLines.close();
                if (settled) return;
                const stderrText = Buffer.concat(stderr).toString("utf8").trim();
                if (resultSeen) {
                    succeed(undefined);
                    return;
                }
                fail(new Error(stderrText || `pi-sandbox ${toolName} failed (${code})`));
            });

            writeFrame({ type: "start", payload: params });
        });
    }

    pi.on("session_start", async (_event, ctx) => {
        state.projectSandboxTrusted = ctx.isProjectTrusted();
        const defaults = await loadConfigDefaults(ctx.cwd, state.projectSandboxTrusted);
        state.sessionKey = deriveSessionKey(ctx);
        state.fs = defaults.fs ?? deriveDefaultFs(pi);
        state.net = defaults.net ?? "none";
        state.outerSandbox = process.env.AGENTWRAP_SANDBOX === "true";
        pendingApprovals.clear();
        approvalPromptQueue.length = 0;
        updateStatus(ctx, state);
    });

    pi.on("session_shutdown", async (_event, ctx) => {
        pendingApprovals.clear();
        approvalPromptQueue.length = 0;
        updateStatus(ctx, state);
        if (!state.sessionKey) return;
    });

    pi.registerCommand("fs", {
        description: "Set pi-sandbox filesystem mode: readonly|write|unrestricted",
        handler: async (args, ctx) => {
            const value = (args || "").trim();
            if (value === "readonly" || value === "r") state.fs = "readonly";
            else if (value === "write" || value === "w") state.fs = "write";
            else if (value === "unrestricted" || value === "u") state.fs = "unrestricted";
            else {
                ctx.ui.notify("Usage: /fs readonly|write|unrestricted", "error");
                return;
            }
            updateStatus(ctx, state);
            ctx.ui.notify(`pi-sandbox status = ${footerLabel(state)}`, "info");
        },
    });

    pi.registerCommand("net", {
        description: "Set pi-sandbox network mode: none|unrestricted|restricted",
        handler: async (args, ctx) => {
            const value = (args || "").trim();
            if (value === "none" || value === "n") state.net = "none";
            else if (value === "unrestricted" || value === "u" || value === "s" || value === "sandboxed") state.net = "unrestricted";
            else if (value === "restricted" || value === "r") state.net = "restricted";
            else {
                ctx.ui.notify("Usage: /net none|unrestricted|restricted", "error");
                return;
            }
            updateStatus(ctx, state);
            ctx.ui.notify(`pi-sandbox status = ${footerLabel(state)}`, "info");
        },
    });

    pi.registerCommand("sandbox-status", {
        description: "Show current pi-sandbox status",
        handler: async (_args, ctx) => {
            ctx.ui.notify(`fs=${state.fs} net=${state.net} footer=${footerLabel(state)} session=${state.sessionKey}`, "info");
        },
    });

    pi.registerTool({
        ...originals.read,
        async execute(id, params, signal, onUpdate, ctx) {
            if (directPassthroughMode(state)) {
                return originals.read.execute(id, params, signal, onUpdate, ctx);
            }
            return makeReadResult(await resolveToolCall("read", params, ctx, signal));
        },
    });

    pi.registerTool({
        ...originals.write,
        async execute(id, params, signal, onUpdate, ctx) {
            if (directPassthroughMode(state)) {
                return originals.write.execute(id, params, signal, onUpdate, ctx);
            }
            const result = await resolveToolCall("write", params, ctx, signal);
            assertSandboxSuccess(result);
            return {
                content: [{ type: "text", text: `Successfully wrote ${result.bytesWritten} bytes to ${params.path}` }],
                details: undefined,
            };
        },
    });

    pi.registerTool({
        ...originals.edit,
        async execute(id, params, signal, onUpdate, ctx) {
            if (directPassthroughMode(state)) {
                return originals.edit.execute(id, params, signal, onUpdate, ctx);
            }
            const result = await resolveToolCall("edit", params, ctx, signal);
            assertSandboxSuccess(result);
            return {
                content: [{ type: "text", text: `Successfully replaced ${result.applied} block(s) in ${params.path}.` }],
                details: undefined,
            };
        },
    });

    pi.registerTool({
        ...originals.ls,
        async execute(id, params, signal, onUpdate, ctx) {
            if (directPassthroughMode(state)) {
                return originals.ls.execute(id, params, signal, onUpdate, ctx);
            }
            return makeTextResult(await resolveToolCall("ls", params, ctx, signal));
        },
    });

    pi.registerTool({
        ...originals.find,
        async execute(id, params, signal, onUpdate, ctx) {
            if (directPassthroughMode(state)) {
                return originals.find.execute(id, params, signal, onUpdate, ctx);
            }
            return makeTextResult(await resolveToolCall("find", params, ctx, signal));
        },
    });

    pi.registerTool({
        ...originals.grep,
        async execute(id, params, signal, onUpdate, ctx) {
            if (directPassthroughMode(state)) {
                return originals.grep.execute(id, params, signal, onUpdate, ctx);
            }
            return makeTextResult(await resolveToolCall("grep", params, ctx, signal));
        },
    });

    pi.registerTool({
        ...originals.bash,
        async execute(id, params, signal, onUpdate, ctx) {
            if (directPassthroughMode(state)) {
                return originals.bash.execute(id, params, signal, onUpdate, ctx);
            }
            const result = await resolveToolCall("bash", params, ctx, signal);
            assertSandboxSuccess(result);
            const output = combineBashOutput(result);
            if (result.timedOut) {
                throw new Error(`${output}\n\nCommand timed out`);
            }
            if ((result.exitCode ?? 0) !== 0) {
                throw new Error(`${output}\n\nCommand exited with code ${result.exitCode}`);
            }
            return {
                content: [{ type: "text", text: output }],
                details: result.truncated ? { truncation: { truncated: true } } : undefined,
            };
        },
    });
}
