import { describe, it, expect, vi, beforeEach } from "vitest";
import * as exec from "./exec.js";
import * as libvirt from "./libvirt.js";
import { capLines, parseSecmodels, listAll, health } from "./local-host.js";

vi.mock("./exec.js");
vi.mock("./libvirt.js", () => ({
  listDomains: vi.fn(),
  domainXml: vi.fn()
}));

describe("local-host helpers", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it("parseSecmodels extracts unique secmodel names", () => {
    const xml = `
      <host>
        <secmodel><model>apparmor</model><doi>0</doi></secmodel>
        <secmodel><model>dac</model><doi>0</doi></secmodel>
        <secmodel><model>apparmor</model><doi>1</doi></secmodel>
      </host>`;
    expect(parseSecmodels(xml)).toEqual(["apparmor", "dac"]);
  });

  it("capLines drops blank lines and enforces the limit", () => {
    expect(capLines("a\n\nb\nc", 2)).toEqual(["a", "b"]);
  });

  it("listAll enriches domains with seclabels and disks", async () => {
    vi.mocked(libvirt.listDomains).mockResolvedValue([
      { id: undefined, name: "Whonix-Gateway", uuid: "u1", state: "shut off", uri: "qemu:///system" }
    ]);
    vi.mocked(libvirt.domainXml).mockResolvedValue(`
      <domain>
        <devices>
          <disk><source file="/mnt/data/libvirt/images/Whonix-Gateway.qcow2"/></disk>
          <disk><source pool="default" volume="extra.qcow2"/></disk>
        </devices>
        <seclabel type='dynamic' model='dac' relabel='yes'/>
        <seclabel type='dynamic' model='apparmor' relabel='yes'/>
      </domain>`);

    const result = await listAll();

    expect(result.domains).toHaveLength(1);
    expect(result.domains[0].seclabel).toEqual(["dac", "apparmor"]);
    expect(result.domains[0].disks).toEqual([
      "/mnt/data/libvirt/images/Whonix-Gateway.qcow2",
      "default:extra.qcow2"
    ]);
    expect(result.connections).toEqual(expect.arrayContaining(["qemu:///system"]));
  });

  it("health aggregates bounded read-only evidence", async () => {
    const mockSh = vi.mocked(exec.sh);
    mockSh.mockImplementation(async (cmd: string, args: string[]) => {
      if (cmd === "systemctl" && args[0] === "is-active") {
        return { stdout: args[1] === "libvirtd" ? "inactive\n" : "active\n", stderr: "" };
      }
      if (cmd === "virsh" && args.includes("capabilities")) {
        return {
          stdout: "<secmodel><model>apparmor</model></secmodel><secmodel><model>dac</model></secmodel>",
          stderr: ""
        };
      }
      if (cmd === "pacman") return { stdout: "libvirt 1:12.9.0-2\n", stderr: "" };
      if (cmd === "virsh" && args.includes("net-list")) {
        return { stdout: " Name   State\n offsec-nat active\n", stderr: "" };
      }
      if (cmd === "virsh" && args.includes("pool-list")) {
        return { stdout: " Name   State\n default active\n", stderr: "" };
      }
      if (cmd === "free") return { stdout: "Mem: 15Gi 11Gi 4Gi\n", stderr: "" };
      if (cmd === "df") return { stdout: "/dev/nvme 475G 149G 324G 32% /\n", stderr: "" };
      if (cmd === "ip") {
        return { stdout: "lo UNKNOWN\nvirbr-nat DOWN\nvirbr-nat 192.168.50.1/24\nmihomo UNKNOWN\n", stderr: "" };
      }
      if (cmd === "journalctl" && args.includes("-u")) {
        return { stdout: "Nov 22 virtqemud: error: something failed\nNov 22 virtqemud: ok\n", stderr: "" };
      }
      if (cmd === "journalctl" && args.includes("-k")) {
        return { stdout: 'apparmor="DENIED" operation="open"\nother line\n', stderr: "" };
      }
      throw new Error(`unexpected command ${cmd} ${args.join(" ")}`);
    });

    const result = await health();

    expect(result.secmodel).toEqual(["apparmor", "dac"]);
    expect(result.package).toBe("libvirt 1:12.9.0-2");
    expect(result.services.libvirtd).toBe("inactive");
    expect(result.services.virtqemud).toBe("active");
    expect(result.libvirtErrors).toHaveLength(1);
    expect(result.apparmorDenials).toHaveLength(1);
    expect(result.resources.interfaces).toContain("virbr-nat DOWN");
    expect(result.resources.interfaces).not.toContain("lo UNKNOWN");
    expect(result.networks).toContain("offsec-nat active");
  });
});
