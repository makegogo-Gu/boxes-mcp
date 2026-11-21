import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { readFile, unlink } from "node:fs/promises";
import * as libvirt from "./libvirt.js";
import {
  BASELINE_SNAPSHOT,
  localStart,
  localShutdown,
  localSnapshot,
  auditPath
} from "./local-lifecycle.js";

vi.mock("./libvirt.js", () => ({
  domainInfo: vi.fn(),
  startDomain: vi.fn(),
  shutdownDomain: vi.fn(),
  listSnapshots: vi.fn(),
  createSnapshot: vi.fn(),
  revertSnapshot: vi.fn(),
  deleteSnapshot: vi.fn()
}));

describe("local lifecycle safety gates", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    process.env.BOXES_MCP_AUDIT_PATH = "/tmp/boxes-mcp-audit-test.jsonl";
    vi.mocked(libvirt.domainInfo).mockResolvedValue({ State: "shut off" });
    vi.mocked(libvirt.startDomain).mockResolvedValue({ ok: true });
    vi.mocked(libvirt.shutdownDomain).mockResolvedValue({ ok: true });
    vi.mocked(libvirt.listSnapshots).mockResolvedValue([{ name: BASELINE_SNAPSHOT, current: false }]);
    vi.mocked(libvirt.createSnapshot).mockResolvedValue({ ok: true });
    vi.mocked(libvirt.revertSnapshot).mockResolvedValue({ ok: true });
    vi.mocked(libvirt.deleteSnapshot).mockResolvedValue({ ok: true });
  });

  afterEach(async () => {
    await unlink(auditPath()).catch(() => undefined);
    delete process.env.BOXES_MCP_AUDIT_PATH;
  });

  async function auditLines(): Promise<string[]> {
    const text = await readFile(auditPath(), "utf8");
    return text.trim().split("\n").filter(Boolean);
  }

  it("requires confirm=true for write operations", async () => {
    await expect(localStart({ nameOrUuid: "kali-offsec" })).rejects.toThrow("confirm=true");
    await expect(localShutdown({ nameOrUuid: "kali-offsec" })).rejects.toThrow("confirm=true");
    await expect(localSnapshot({ nameOrUuid: "kali-offsec", action: "create", snapshot: "s1" })).rejects.toThrow("confirm=true");
    expect(libvirt.startDomain).not.toHaveBeenCalled();
    expect(libvirt.shutdownDomain).not.toHaveBeenCalled();
  });

  it("enforces Whonix start and shutdown ordering", async () => {
    vi.mocked(libvirt.domainInfo).mockResolvedValue({ State: "shut off" });
    await expect(localStart({ nameOrUuid: "Whonix-Workstation", confirm: true })).rejects.toThrow("Gateway must be running");

    vi.mocked(libvirt.domainInfo).mockImplementation(async (name: string) =>
      ({ State: name === "Whonix-Gateway" ? "running" : "shut off" })
    );
    await expect(localStart({ nameOrUuid: "WS-identityA", confirm: true })).resolves.toMatchObject({ ok: true });
    expect(libvirt.startDomain).toHaveBeenCalledWith("WS-identityA");

    vi.mocked(libvirt.domainInfo).mockResolvedValue({ State: "running" });
    await expect(localShutdown({ nameOrUuid: "Whonix-Gateway", confirm: true })).rejects.toThrow("still running");
  });

  it("protects the baseline snapshot unless explicitly allowed", async () => {
    await expect(localSnapshot({
      nameOrUuid: "kali-offsec", action: "revert", snapshot: BASELINE_SNAPSHOT, confirm: true
    })).rejects.toThrow("protected");
    expect(libvirt.revertSnapshot).not.toHaveBeenCalled();

    await expect(localSnapshot({
      nameOrUuid: "kali-offsec", action: "revert", snapshot: BASELINE_SNAPSHOT, confirm: true, allowBaseline: true
    })).resolves.toMatchObject({ ok: true, action: "revert" });
    expect(libvirt.revertSnapshot).toHaveBeenCalledWith("kali-offsec", BASELINE_SNAPSHOT);
  });

  it("audits successful and rejected attempts as JSONL", async () => {
    await localStart({ nameOrUuid: "kali-offsec" }).catch(() => undefined); // rejected: no confirm
    await localShutdown({ nameOrUuid: "kali-offsec", confirm: true, force: true });
    await localSnapshot({ nameOrUuid: "kali-offsec", action: "list" });

    const lines = await auditLines();
    expect(lines).toHaveLength(3);
    const parsed = lines.map(line => JSON.parse(line));
    expect(parsed[0]).toMatchObject({ tool: "local.start", ok: false, confirm: false });
    expect(parsed[1]).toMatchObject({ tool: "local.shutdown", action: "force-off", ok: true });
    expect(parsed[2]).toMatchObject({ tool: "local.snapshot", action: "list", ok: true });
  });
});
