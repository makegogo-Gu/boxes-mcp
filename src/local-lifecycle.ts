// Write-capable local VM operations with explicit confirmation, ordering
// guards, and an append-only JSONL audit trail.
//
// Safety contract:
//  - no operation runs unless the caller passes `confirm: true`;
//  - Whonix ordering is enforced (Gateway before Workstation start, reverse for stop);
//  - the baseline snapshot cannot be reverted/deleted without `allowBaseline: true`;
//  - every attempt (success or failure) is appended to BOXES_MCP_AUDIT_PATH.

import { appendFile, mkdir, unlink } from "node:fs/promises";
import { dirname, join } from "node:path";
import { homedir, tmpdir } from "node:os";
import { BoxesError } from "./errors.js";
import {
  domainInfo,
  startDomain,
  shutdownDomain,
  listSnapshots,
  createSnapshot,
  revertSnapshot,
  deleteSnapshot
} from "./libvirt.js";

export const BASELINE_SNAPSHOT = "pre-mcp-20261122";

export function auditPath(): string {
  return process.env.BOXES_MCP_AUDIT_PATH || join(homedir(), ".pi", "agent", "boxes-mcp-audit.jsonl");
}

interface AuditEntry {
  at: string;
  tool: string;
  domain: string;
  action: string;
  confirm: boolean;
  ok: boolean;
  error?: string;
}

async function audit(entry: AuditEntry): Promise<void> {
  try {
    const path = auditPath();
    await mkdir(dirname(path), { recursive: true });
    await appendFile(path, `${JSON.stringify(entry)}\n`, { mode: 0o600 });
  } catch (error) {
    process.stderr.write(`[local-lifecycle] audit write failed: ${error instanceof Error ? error.message : String(error)}\n`);
  }
}

export function requireConfirm(confirm: unknown): void {
  if (confirm !== true) {
    throw new BoxesError("INVALID_ARGUMENT", "Set confirm=true to execute this write operation");
  }
}

function isWorkstation(name: string): boolean {
  return name === "Whonix-Workstation" || name.startsWith("WS-");
}

async function stateOf(nameOrUuid: string): Promise<string> {
  const info = await domainInfo(nameOrUuid);
  return (info.State || "").toLowerCase();
}

async function withAudit<T>(
  tool: string,
  domain: string,
  action: string,
  confirm: boolean,
  fn: () => Promise<T>
): Promise<T> {
  try {
    const result = await fn();
    await audit({ at: new Date().toISOString(), tool, domain, action, confirm, ok: true });
    return result;
  } catch (error) {
    await audit({
      at: new Date().toISOString(),
      tool,
      domain,
      action,
      confirm,
      ok: false,
      error: error instanceof Error ? error.message : String(error)
    });
    throw error;
  }
}

export interface StartArgs {
  nameOrUuid: string;
  confirm?: boolean;
}

export async function localStart(args: StartArgs) {
  const name = args.nameOrUuid;
  return withAudit("local.start", name, "start", args.confirm === true, async () => {
    requireConfirm(args.confirm);
    if (isWorkstation(name)) {
      const gatewayState = await stateOf("Whonix-Gateway");
      if (gatewayState !== "running") {
        throw new BoxesError("DOMAIN_NOT_RUNNING", `Whonix-Gateway must be running before ${name} (state=${gatewayState})`);
      }
    }
    await startDomain(name);
    return { ok: true, domain: name, order: isWorkstation(name) ? "gateway-first" : "normal" };
  });
}

export interface ShutdownArgs {
  nameOrUuid: string;
  confirm?: boolean;
  force?: boolean;
}

export async function localShutdown(args: ShutdownArgs) {
  const name = args.nameOrUuid;
  return withAudit("local.shutdown", name, args.force ? "force-off" : "shutdown", args.confirm === true, async () => {
    requireConfirm(args.confirm);
    if (name === "Whonix-Gateway") {
      const wsState = await stateOf("Whonix-Workstation");
      if (wsState === "running") {
        throw new BoxesError("INVALID_ARGUMENT", "Whonix-Workstation is still running; shut it down before the Gateway");
      }
    }
    await shutdownDomain(name, args.force ?? false);
    return { ok: true, domain: name, force: args.force ?? false };
  });
}

export type SnapshotAction = "list" | "create" | "revert" | "delete";

export interface SnapshotArgs {
  nameOrUuid: string;
  action: SnapshotAction;
  snapshot?: string;
  description?: string;
  allowBaseline?: boolean;
  confirm?: boolean;
}

export async function localSnapshot(args: SnapshotArgs) {
  const name = args.nameOrUuid;
  const action = args.action;
  const writeAction = action !== "list";

  return withAudit("local.snapshot", name, action, writeAction && args.confirm === true, async () => {
    if (writeAction) requireConfirm(args.confirm);
    if (writeAction && !args.snapshot) {
      throw new BoxesError("INVALID_ARGUMENT", "snapshot name is required for create/revert/delete");
    }
    if ((action === "revert" || action === "delete") && args.snapshot === BASELINE_SNAPSHOT && !args.allowBaseline) {
      throw new BoxesError("INVALID_ARGUMENT", `Baseline snapshot ${BASELINE_SNAPSHOT} is protected; set allowBaseline=true to override`);
    }
    switch (action) {
      case "list":
        return { ok: true, domain: name, snapshots: await listSnapshots(name) };
      case "create":
        await createSnapshot(name, args.snapshot as string, args.description);
        return { ok: true, domain: name, snapshot: args.snapshot, action: "create" };
      case "revert":
        await revertSnapshot(name, args.snapshot as string);
        return { ok: true, domain: name, snapshot: args.snapshot, action: "revert" };
      case "delete":
        await deleteSnapshot(name, args.snapshot as string);
        return { ok: true, domain: name, snapshot: args.snapshot, action: "delete" };
      default:
        throw new BoxesError("INVALID_ARGUMENT", `Unknown snapshot action: ${action}`);
    }
  });
}

/** Test helper: remove a temporary audit file. Not exported through MCP tools. */
export async function removeAuditFile(path: string): Promise<void> {
  await unlink(path).catch(() => undefined);
}

/** Default temporary audit location for isolated tests. */
export const TEST_AUDIT_PATH = join(tmpdir(), "boxes-mcp-audit-test.jsonl");
