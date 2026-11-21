// Read-only, host-local helpers built on the existing safe exec boundary.
//
// This module deliberately exposes no lifecycle operations. It answers two
// questions for an agent: "what VMs exist on this host?" and "is the local
// virtualization stack healthy?". Every command is a fixed argument array
// passed to exec.sh(); no shell fragments and no caller-supplied commands.

import { sh } from "./exec.js";
import { VIRSH, URIS, DEFAULT_URI, commonArgsFor } from "./virsh.js";
import { listDomains, domainXml, type DomainSummary } from "./libvirt.js";

export interface LocalDomain extends DomainSummary {
  seclabel: string[];
  disks: string[];
}

export interface LocalDomainList {
  connections: string[];
  domains: LocalDomain[];
}

export interface LocalHealth {
  checkedAt: string;
  connections: string[];
  secmodel: string[];
  package: string;
  services: Record<string, string>;
  networks: string[];
  pools: string[];
  resources: {
    memory: string[];
    disk: string[];
    interfaces: string[];
  };
  libvirtErrors: string[];
  apparmorDenials: string[];
}

export function capLines(text: string, limit = 20): string[] {
  return text.split("\n").map(line => line.trim()).filter(Boolean).slice(0, limit);
}

/** Extract secmodel names from `virsh capabilities` XML. */
export function parseSecmodels(xml: string): string[] {
  const models: string[] = [];
  const re = /<secmodel>[\s\S]*?<model>([^<]+)<\/model>/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(xml)) !== null) {
    const model = match[1].trim();
    if (model && !models.includes(model)) models.push(model);
  }
  return models;
}

function parseSeclabels(xml: string): string[] {
  const out: string[] = [];
  const re = /<seclabel\b[^>]*\bmodel=['"]([^'"]+)['"][^>]*>/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(xml)) !== null) {
    if (!out.includes(match[1])) out.push(match[1]);
  }
  return out;
}

function parseDisks(xml: string): string[] {
  const out: string[] = [];
  const fileRe = /<source\s+file=['"]([^'"]+)['"][^>]*\/?>/g;
  const volRe = /<source\s+pool=['"]([^'"]+)['"]\s+volume=['"]([^'"]+)['"][^>]*\/?>/g;
  let match: RegExpExecArray | null;
  while ((match = fileRe.exec(xml)) !== null) out.push(match[1]);
  while ((match = volRe.exec(xml)) !== null) out.push(`${match[1]}:${match[2]}`);
  return out;
}

export async function listAll(): Promise<LocalDomainList> {
  const domains = await listDomains();
  const enriched: LocalDomain[] = [];
  for (const domain of domains) {
    let seclabel: string[] = [];
    let disks: string[] = [];
    try {
      const xml = await domainXml(domain.name);
      seclabel = parseSeclabels(xml);
      disks = parseDisks(xml);
    } catch {
      // Domain XML may be unavailable for transient/unmanaged domains;
      // keep the basic summary rather than failing the whole list.
    }
    enriched.push({ ...domain, seclabel, disks });
  }
  return { connections: URIS, domains: enriched };
}

type SafeResult = { ok: boolean; stdout: string; stderr: string };

async function safeSh(cmd: string, args: string[]): Promise<SafeResult> {
  try {
    const result = await sh(cmd, args);
    return { ok: true, stdout: result.stdout.trim(), stderr: result.stderr.trim() };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { ok: false, stdout: "", stderr: message };
  }
}

const SERVICES = ["libvirtd", "virtqemud", "virtnetworkd", "docker", "docker-egress-guard", "mihomo"];

export async function health(): Promise<LocalHealth> {
  const services: Record<string, string> = {};
  for (const service of SERVICES) {
    const result = await safeSh("systemctl", ["is-active", service]);
    services[service] = result.stdout || "unavailable";
  }

  const capabilities = await safeSh(VIRSH, [...commonArgsFor(DEFAULT_URI), "capabilities"]);
  const packageInfo = await safeSh("pacman", ["-Q", "libvirt"]);
  const netList = await safeSh(VIRSH, [...commonArgsFor(DEFAULT_URI), "net-list", "--all"]);
  const poolList = await safeSh(VIRSH, [...commonArgsFor(DEFAULT_URI), "pool-list", "--all"]);
  const memory = await safeSh("free", ["-h"]);
  const disk = await safeSh("df", ["-h", "/", "/mnt/data"]);
  const interfaces = await safeSh("ip", ["-br", "addr"]);
  const journal = await safeSh("journalctl", ["-u", "virtqemud", "--no-pager", "-n", "30"]);
  const kernel = await safeSh("journalctl", ["-k", "--no-pager", "-n", "100"]);

  const libvirtErrors = capLines(journal.stdout)
    .filter(line => /error|denied|apparmor|failed/i.test(line))
    .slice(0, 10);
  const apparmorDenials = capLines(kernel.stdout, 100)
    .filter(line => /apparmor="DENIED"/i.test(line))
    .slice(0, 10);

  return {
    checkedAt: new Date().toISOString(),
    connections: URIS,
    secmodel: parseSecmodels(capabilities.stdout),
    package: packageInfo.stdout || "unknown",
    services,
    networks: capLines(netList.stdout),
    pools: capLines(poolList.stdout),
    resources: {
      memory: capLines(memory.stdout),
      disk: capLines(disk.stdout),
      interfaces: capLines(interfaces.stdout, 100).filter(line => /virbr|mihomo|wlan0/.test(line))
    },
    libvirtErrors,
    apparmorDenials
  };
}
