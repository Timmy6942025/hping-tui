import { createCliRenderer, TextAttributes } from "@opentui/core";
import { createRoot, useKeyboard, useRenderer } from "@opentui/react";
import { useState, useEffect, useRef, useCallback } from "react";
import { spawn, ChildProcess } from "child_process";
import { writeFileSync, mkdirSync, readFileSync } from "fs";
import { homedir } from "os";
import { join } from "path";

type Protocol = "tcp" | "udp" | "icmp";

interface HpingConfig {
  target: string;
  protocol: Protocol;
  port: string;
  count: string;
  interval: string;
  flags: { syn: boolean; ack: boolean; fin: boolean; rst: boolean; psh: boolean; urg: boolean };
  dataLength: string;
  ttl: string;
  flood: boolean;
  fast: boolean;
  traceroute: boolean;
  spoofIp: string;
  verbose: boolean;
  noDns: boolean;
  windowSize: string;
  randSource: boolean;
}

interface HpingStats {
  packetsSent: number;
  packetsReceived: number;
  packetLoss: string;
  rttMin: string;
  rttAvg: string;
  rttMax: string;
  rttMdev: string;
}

interface OutputLine {
  type: string;
  content: string;
  timestamp: string;
}

const DEFAULT_CONFIG: HpingConfig = {
  target: "",
  protocol: "tcp",
  port: "80",
  count: "",
  interval: "1",
  flags: { syn: true, ack: false, fin: false, rst: false, psh: false, urg: false },
  dataLength: "0",
  ttl: "64",
  flood: false,
  fast: false,
  traceroute: false,
  spoofIp: "",
  verbose: false,
  noDns: false,
  windowSize: "",
  randSource: false,
};

const PRESETS: { name: string; key: string; config: Partial<HpingConfig> }[] = [
  { name: "SYN Scan", key: "F1", config: { protocol: "tcp", flags: { syn: true, ack: false, fin: false, rst: false, psh: false, urg: false }, port: "80", count: "10" } },
  { name: "Firewall", key: "F2", config: { protocol: "tcp", flags: { syn: true, ack: true, fin: false, rst: false, psh: false, urg: false }, port: "443", count: "20" } },
  { name: "ICMP Ping", key: "F3", config: { protocol: "icmp", flags: { syn: false, ack: false, fin: false, rst: false, psh: false, urg: false }, port: "", count: "10" } },
  { name: "Traceroute", key: "F4", config: { protocol: "tcp", traceroute: true, flags: { syn: true, ack: false, fin: false, rst: false, psh: false, urg: false }, port: "80", count: "30" } },
  { name: "UDP Test", key: "F5", config: { protocol: "udp", flags: { syn: false, ack: false, fin: false, rst: false, psh: false, urg: false }, port: "53", count: "10" } },
  { name: "XMAS Scan", key: "F6", config: { protocol: "tcp", flags: { syn: false, ack: false, fin: true, rst: false, psh: true, urg: true }, port: "80", count: "5" } },
];

const INPUT_FIELDS = ["target", "port", "count", "interval", "dataSize", "ttl", "winSize", "spoofIp"] as const;

function buildHpingArgs(c: HpingConfig): string[] {
  const a: string[] = [];
  if (c.noDns) a.push("-n");
  if (c.verbose) a.push("-V");
  if (c.protocol === "icmp") a.push("-1");
  else if (c.protocol === "udp") a.push("-2");
  if (c.protocol !== "icmp" && c.port) a.push("-p", c.port);
  if (c.count) a.push("-c", c.count);
  if (c.interval) a.push("-i", c.interval);
  if (c.dataLength && parseInt(c.dataLength) > 0) a.push("-d", c.dataLength);
  if (c.ttl) a.push("--ttl", c.ttl);
  if (c.windowSize && parseInt(c.windowSize) > 0) a.push("--win", c.windowSize);
  if (c.flags.syn) a.push("-S");
  if (c.flags.ack) a.push("-A");
  if (c.flags.fin) a.push("-F");
  if (c.flags.rst) a.push("-R");
  if (c.flags.psh) a.push("-P");
  if (c.flags.urg) a.push("-U");
  if (c.flood) a.push("--flood");
  if (c.fast) a.push("--fast");
  if (c.traceroute) a.push("--traceroute");
  if (c.spoofIp) a.push("-a", c.spoofIp);
  if (c.randSource) a.push("--rand-source");
  a.push(c.target);
  return a;
}

function parseStatsLine(line: string): Partial<HpingStats> | null {
  const s: Partial<HpingStats> = {};
  const m1 = line.match(/(\d+)\s+packets?\s+transmitted/);
  if (m1?.[1]) s.packetsSent = parseInt(m1[1]);
  const m2 = line.match(/(\d+)\s+packets?\s+received/);
  if (m2?.[1]) s.packetsReceived = parseInt(m2[1]);
  const m3 = line.match(/([\d.]+)%\s+packets?\s+lost/);
  if (m3?.[1]) s.packetLoss = m3[1] + "%";
  const m4 = line.match(/round-trip\s+min\/avg\/max\s+=\s+([\d.]+)\/([\d.]+)\/([\d.]+)\/?([\d.]*)\s+ms/);
  if (m4?.[1] && m4[2] && m4[3]) {
    s.rttMin = m4[1] + " ms"; s.rttAvg = m4[2] + " ms"; s.rttMax = m4[3] + " ms";
    if (m4[4]) s.rttMdev = m4[4] + " ms";
  }
  return Object.keys(s).length > 0 ? s : null;
}

function parseOutputLine(line: string): OutputLine {
  let type = "info";
  if (line.includes("len=") || line.includes("seq=")) type = "response";
  else if (line.includes("traceroute") || line.includes("HOP")) type = "traceroute";
  else if (line.includes("packets transmitted") || line.includes("packets received") || line.includes("round-trip")) type = "stats";
  else if (line.startsWith("HPING")) type = "header";
  else if (line.toLowerCase().includes("error") || line.toLowerCase().includes("fail") || line.includes("can't")) type = "error";
  return { type, content: line, timestamp: new Date().toLocaleTimeString() };
}

function lineColor(type: string): string {
  switch (type) {
    case "response": return "#00ff00";
    case "stats": return "#ffff00";
    case "header": return "#00ffff";
    case "error": return "#ff4444";
    case "traceroute": return "#ff00ff";
    default: return "#aaaaaa";
  }
}

function lossBar(loss: string): string {
  const n = parseFloat(loss);
  if (isNaN(n)) return "";
  const f = Math.round((n / 100) * 10);
  return "\u2588".repeat(f) + "\u2591".repeat(10 - f);
}

function loadConfig(): HpingConfig {
  try {
    return { ...DEFAULT_CONFIG, ...JSON.parse(readFileSync(join(homedir(), ".hping-tui", "config.json"), "utf-8")) };
  } catch { return { ...DEFAULT_CONFIG }; }
}

function saveConfig(c: HpingConfig) {
  try {
    mkdirSync(join(homedir(), ".hping-tui"), { recursive: true });
    writeFileSync(join(homedir(), ".hping-tui", "config.json"), JSON.stringify(c, null, 2));
  } catch { /* ignore */ }
}

function App() {
  const [config, setConfig] = useState<HpingConfig>(loadConfig);
  const [outputLines, setOutputLines] = useState<OutputLine[]>([]);
  const [stats, setStats] = useState<HpingStats | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [focusedField, setFocusedField] = useState("target");
  const [showHelp, setShowHelp] = useState(false);
  const [filter, setFilter] = useState<Set<string>>(new Set(["response", "stats", "header", "info", "traceroute", "error"]));
  const processRef = useRef<ChildProcess | null>(null);
  const renderer = useRenderer();

  const runHping = useCallback(() => {
    if (!config.target) { setError("Target host is required"); return; }
    if (processRef.current) processRef.current.kill("SIGTERM");
    setError(null); setOutputLines([]); setStats(null);
    const args = buildHpingArgs(config);
    setOutputLines([
      { type: "header", content: `$ hping3 ${args.join(" ")}`, timestamp: new Date().toLocaleTimeString() },
      { type: "info", content: `Starting hping3 to ${config.target}...`, timestamp: new Date().toLocaleTimeString() },
    ]);
    try {
      const proc = spawn("sudo", ["hping3", ...args], { shell: false });
      processRef.current = proc; setIsRunning(true);
      proc.stdout.on("data", (data: Buffer) => {
        const lines = data.toString().split("\n").filter((l) => l.trim());
        setOutputLines((prev) => [...prev, ...lines.map(parseOutputLine)]);
        for (const line of lines) { const p = parseStatsLine(line); if (p) setStats((prev) => ({ ...prev, ...p } as HpingStats)); }
      });
      proc.stderr.on("data", (data: Buffer) => {
        const lines = data.toString().split("\n").filter((l) => l.trim());
        setOutputLines((prev) => [...prev, ...lines.map((l) => ({ type: "error", content: l, timestamp: new Date().toLocaleTimeString() } as OutputLine))]);
      });
      proc.on("close", (code: number) => {
        setIsRunning(false); processRef.current = null;
        setOutputLines((prev) => [...prev, { type: "info", content: `Process exited with code ${code}`, timestamp: new Date().toLocaleTimeString() }]);
      });
      proc.on("error", (err: Error) => {
        setIsRunning(false); processRef.current = null;
        setError(`Failed to start hping3: ${err.message}`);
      });
    } catch (err: any) { setError(`Failed to spawn: ${err.message}`); setIsRunning(false); }
  }, [config]);

  const stopHping = useCallback(() => {
    if (processRef.current) {
      processRef.current.kill("SIGTERM"); processRef.current = null; setIsRunning(false);
      setOutputLines((prev) => [...prev, { type: "info", content: "Process stopped", timestamp: new Date().toLocaleTimeString() }]);
    }
  }, []);

  const saveLog = useCallback(() => {
    try {
      mkdirSync(join(homedir(), ".hping-tui"), { recursive: true });
      const path = join(homedir(), ".hping-tui", `hping-${new Date().toISOString().replace(/[:.]/g, "-")}.log`);
      writeFileSync(path, outputLines.map((l) => `[${l.timestamp}] ${l.content}`).join("\n"));
      setOutputLines((prev) => [...prev, { type: "info", content: `Log saved to ${path}`, timestamp: new Date().toLocaleTimeString() }]);
    } catch (err: any) { setError(`Failed to save log: ${err.message}`); }
  }, [outputLines]);

  const cycleField = useCallback((dir: 1 | -1) => {
    setFocusedField((prev) => {
      const idx = INPUT_FIELDS.indexOf(prev as typeof INPUT_FIELDS[number]);
      return INPUT_FIELDS[(idx + dir + INPUT_FIELDS.length) % INPUT_FIELDS.length];
    });
  }, []);

  const updateField = useCallback((field: string, value: string) => {
    const map: Record<string, string> = { dataSize: "dataLength", winSize: "windowSize" };
    setConfig((prev) => ({ ...prev, [map[field] ?? field]: value }));
  }, []);

  useKeyboard((key) => {
    if (showHelp && (key.name === "escape" || (key.ctrl && key.name === "h"))) { setShowHelp(false); return; }
    if (key.ctrl && key.name === "c") { stopHping(); saveConfig(config); renderer.destroy(); return; }
    if (key.ctrl && key.name === "h") { setShowHelp((v) => !v); return; }
    if (key.ctrl && key.name === "r") { runHping(); return; }
    if (key.ctrl && key.name === "s") { stopHping(); return; }
    if (key.ctrl && key.name === "o") { saveLog(); return; }
    if (key.name === "tab" && !key.shift) { cycleField(1); return; }
    if ((key.name === "tab" && key.shift) || key.name === "iso_left_tab") { cycleField(-1); return; }
    if (key.name === "down") { cycleField(1); return; }
    if (key.name === "up") { cycleField(-1); return; }
    if (key.name === "f1") { setConfig((p) => ({ ...p, ...PRESETS[0].config })); return; }
    if (key.name === "f2") { setConfig((p) => ({ ...p, ...PRESETS[1].config })); return; }
    if (key.name === "f3") { setConfig((p) => ({ ...p, ...PRESETS[2].config })); return; }
    if (key.name === "f4") { setConfig((p) => ({ ...p, ...PRESETS[3].config })); return; }
    if (key.name === "f5") { setConfig((p) => ({ ...p, ...PRESETS[4].config })); return; }
    if (key.name === "f6") { setConfig((p) => ({ ...p, ...PRESETS[5].config })); return; }
    if (key.ctrl && key.name === "1") { setConfig((p) => ({ ...p, protocol: "tcp" })); return; }
    if (key.ctrl && key.name === "2") { setConfig((p) => ({ ...p, protocol: "udp" })); return; }
    if (key.ctrl && key.name === "3") { setConfig((p) => ({ ...p, protocol: "icmp" })); return; }
    if (key.ctrl && key.name === "y") { setConfig((p) => ({ ...p, flags: { ...p.flags, syn: !p.flags.syn } })); return; }
    if (key.ctrl && key.name === "a") { setConfig((p) => ({ ...p, flags: { ...p.flags, ack: !p.flags.ack } })); return; }
    if (key.ctrl && key.name === "f") { setConfig((p) => ({ ...p, flags: { ...p.flags, fin: !p.flags.fin } })); return; }
    if (key.ctrl && key.name === "d") { setConfig((p) => ({ ...p, flags: { ...p.flags, rst: !p.flags.rst } })); return; }
    if (key.ctrl && key.name === "p") { setConfig((p) => ({ ...p, flags: { ...p.flags, psh: !p.flags.psh } })); return; }
    if (key.ctrl && key.name === "u") { setConfig((p) => ({ ...p, flags: { ...p.flags, urg: !p.flags.urg } })); return; }
    if (key.ctrl && key.name === "g") { setConfig((p) => ({ ...p, flood: !p.flood })); return; }
    if (key.ctrl && key.name === "k") { setConfig((p) => ({ ...p, fast: !p.fast })); return; }
    if (key.ctrl && key.name === "t") { setConfig((p) => ({ ...p, traceroute: !p.traceroute })); return; }
    if (key.ctrl && key.name === "v") { setConfig((p) => ({ ...p, verbose: !p.verbose })); return; }
    if (key.ctrl && key.name === "n") { setConfig((p) => ({ ...p, noDns: !p.noDns })); return; }
    if (key.ctrl && key.name === "z") { setConfig((p) => ({ ...p, randSource: !p.randSource })); return; }
    if (key.shift && key.name === "r") { setFilter((prev) => { const n = new Set(prev); n.has("response") ? n.delete("response") : n.add("response"); return n; }); return; }
    if (key.shift && key.name === "s") { setFilter((prev) => { const n = new Set(prev); n.has("stats") ? n.delete("stats") : n.add("stats"); return n; }); return; }
    if (key.shift && key.name === "e") { setFilter((prev) => { const n = new Set(prev); n.has("error") ? n.delete("error") : n.add("error"); return n; }); return; }
    if (key.shift && key.name === "i") { setFilter((prev) => { const n = new Set(prev); n.has("info") ? n.delete("info") : n.add("info"); n.has("header") ? n.delete("header") : n.add("header"); return n; }); return; }
  });

  useEffect(() => { () => { if (processRef.current) processRef.current.kill("SIGTERM"); saveConfig(config); }; }, []);
  useEffect(() => { saveConfig(config); }, [config]);

  const filteredLines = outputLines.filter((l) => filter.has(l.type)).slice(-300);
  const cmd = buildHpingArgs(config).join(" ");

  return (
    <box flexDirection="column" flexGrow={1}>
      {/* Header */}
      <box flexDirection="row" alignItems="center" paddingX={1} borderBottom borderStyle="single">
        <text fg="#00ffff" attributes={TextAttributes.BOLD}>hping-tui</text>
        <text attributes={TextAttributes.DIM}> — Interactive hping3 Terminal UI</text>
        <box flexGrow={1} />
        <text fg="#00ffff">v1.0.6</text>
      </box>

      {/* Presets */}
      <box flexDirection="row" gap={2} paddingX={1}>
        {PRESETS.map((p) => (
          <box key={p.name}>
            <text attributes={TextAttributes.DIM}>{p.key}</text>
            <text> {p.name} </text>
          </box>
        ))}
      </box>

      {/* Main content */}
      <box flexDirection="row" flexGrow={1}>
        {/* Left panel - Config */}
        <box width={40} border borderStyle="single" flexDirection="column" paddingX={1}>
          <box>
            <text attributes={TextAttributes.BOLD}>Configuration</text>
          </box>

          <box flexDirection="column">
            <box flexDirection="row">
              <text width={8} attributes={focusedField === "target" ? TextAttributes.BOLD : TextAttributes.DIM}>Target:</text>
              <input value={config.target} onChange={(v) => updateField("target", v)} focused={focusedField === "target"} width={28} placeholder="host" />
            </box>
            <box flexDirection="row">
              <text width={8} attributes={focusedField === "port" ? TextAttributes.BOLD : TextAttributes.DIM}>Port:</text>
              <input value={config.port} onChange={(v) => updateField("port", v)} focused={focusedField === "port"} width={28} placeholder="80" />
            </box>
            <box flexDirection="row">
              <text width={8} attributes={focusedField === "count" ? TextAttributes.BOLD : TextAttributes.DIM}>Count:</text>
              <input value={config.count} onChange={(v) => updateField("count", v)} focused={focusedField === "count"} width={28} placeholder="inf" />
            </box>
            <box flexDirection="row">
              <text width={8} attributes={focusedField === "interval" ? TextAttributes.BOLD : TextAttributes.DIM}>Intvl:</text>
              <input value={config.interval} onChange={(v) => updateField("interval", v)} focused={focusedField === "interval"} width={28} placeholder="1" />
            </box>
            <box flexDirection="row">
              <text width={8} attributes={focusedField === "dataSize" ? TextAttributes.BOLD : TextAttributes.DIM}>Data:</text>
              <input value={config.dataLength} onChange={(v) => updateField("dataSize", v)} focused={focusedField === "dataSize"} width={28} placeholder="0" />
            </box>
            <box flexDirection="row">
              <text width={8} attributes={focusedField === "ttl" ? TextAttributes.BOLD : TextAttributes.DIM}>TTL:</text>
              <input value={config.ttl} onChange={(v) => updateField("ttl", v)} focused={focusedField === "ttl"} width={28} placeholder="64" />
            </box>
            <box flexDirection="row">
              <text width={8} attributes={focusedField === "winSize" ? TextAttributes.BOLD : TextAttributes.DIM}>Win:</text>
              <input value={config.windowSize} onChange={(v) => updateField("winSize", v)} focused={focusedField === "winSize"} width={28} placeholder="" />
            </box>
            <box flexDirection="row">
              <text width={8} attributes={focusedField === "spoofIp" ? TextAttributes.BOLD : TextAttributes.DIM}>Spoof:</text>
              <input value={config.spoofIp} onChange={(v) => updateField("spoofIp", v)} focused={focusedField === "spoofIp"} width={28} placeholder="" />
            </box>
          </box>

          <box>
            <text attributes={TextAttributes.DIM}>Protocol:</text>
          </box>
          <box flexDirection="row" gap={2}>
            <text attributes={config.protocol === "tcp" ? TextAttributes.BOLD : TextAttributes.DIM}>[Ctrl+1] TCP</text>
            <text attributes={config.protocol === "udp" ? TextAttributes.BOLD : TextAttributes.DIM}>[Ctrl+2] UDP</text>
            <text attributes={config.protocol === "icmp" ? TextAttributes.BOLD : TextAttributes.DIM}>[Ctrl+3] ICMP</text>
          </box>

          <box>
            <text attributes={TextAttributes.DIM}>Flags:</text>
          </box>
          <box flexDirection="column">
            <box flexDirection="row" gap={2}>
              <text attributes={config.flags.syn ? TextAttributes.BOLD : TextAttributes.DIM}>[Ctrl+Y] SYN</text>
              <text attributes={config.flags.ack ? TextAttributes.BOLD : TextAttributes.DIM}>[Ctrl+A] ACK</text>
            </box>
            <box flexDirection="row" gap={2}>
              <text attributes={config.flags.fin ? TextAttributes.BOLD : TextAttributes.DIM}>[Ctrl+F] FIN</text>
              <text attributes={config.flags.rst ? TextAttributes.BOLD : TextAttributes.DIM}>[Ctrl+D] RST</text>
            </box>
            <box flexDirection="row" gap={2}>
              <text attributes={config.flags.psh ? TextAttributes.BOLD : TextAttributes.DIM}>[Ctrl+P] PSH</text>
              <text attributes={config.flags.urg ? TextAttributes.BOLD : TextAttributes.DIM}>[Ctrl+U] URG</text>
            </box>
          </box>

          <box>
            <text attributes={TextAttributes.DIM}>Options:</text>
          </box>
          <box flexDirection="column">
            <box flexDirection="row" gap={2}>
              <text attributes={config.flood ? TextAttributes.BOLD : TextAttributes.DIM}>[Ctrl+G] Flood</text>
              <text attributes={config.fast ? TextAttributes.BOLD : TextAttributes.DIM}>[Ctrl+K] Fast</text>
            </box>
            <box flexDirection="row" gap={2}>
              <text attributes={config.traceroute ? TextAttributes.BOLD : TextAttributes.DIM}>[Ctrl+T] Trace</text>
              <text attributes={config.verbose ? TextAttributes.BOLD : TextAttributes.DIM}>[Ctrl+V] Verbose</text>
            </box>
            <box flexDirection="row" gap={2}>
              <text attributes={config.noDns ? TextAttributes.BOLD : TextAttributes.DIM}>[Ctrl+N] NoDNS</text>
              <text attributes={config.randSource ? TextAttributes.BOLD : TextAttributes.DIM}>[Ctrl+Z] RandSrc</text>
            </box>
          </box>
        </box>

        {/* Right panel - Output */}
        <box flexGrow={1} flexDirection="column" paddingX={1}>
          <box flexDirection="row" justifyContent="space-between">
            <text attributes={TextAttributes.BOLD}>Output</text>
            <text attributes={TextAttributes.DIM}> ({filteredLines.length} lines)</text>
            <text>
              {isRunning ? <span fg="#00ff00">● Running</span> : <span fg="#888888">○ Stopped</span>}
            </text>
          </box>

          <box flexDirection="column" flexGrow={1} border borderStyle="single">
            <scrollbox flexGrow={1} stickyScroll stickyStart="bottom">
              {filteredLines.map((line, i) => (
                <text key={i} fg={lineColor(line.type)}>
                  <span fg="#555555">[{line.timestamp}]</span> {line.content}
                </text>
              ))}
              {filteredLines.length === 0 && (
                <text attributes={TextAttributes.DIM}>Press Ctrl+R to start hping3...</text>
              )}
            </scrollbox>
          </box>

          {stats && (
            <box flexDirection="column">
              <box flexDirection="row" gap={4}>
                <text><span fg="#00ffff">Sent:</span> {stats.packetsSent}</text>
                <text><span fg="#00ffff">Recv:</span> {stats.packetsReceived}</text>
                <text><span fg="#00ffff">Loss:</span> {stats.packetLoss}</text>
                {stats.rttAvg && <text><span fg="#00ffff">RTT:</span> {stats.rttAvg}</text>}
              </box>
              {stats.packetLoss && <text fg="#ff8800">{lossBar(stats.packetLoss)}</text>}
            </box>
          )}
        </box>
      </box>

      {/* Status bar */}
      <box flexDirection="column" borderTop borderStyle="single" paddingX={1}>
        {error && <text fg="#ff4444">{error}</text>}
        <box flexDirection="row" justifyContent="space-between">
          <text fg="#00ff00">hping3 {cmd}</text>
          <text attributes={TextAttributes.DIM}>Field: <span attributes={TextAttributes.BOLD}>{focusedField}</span></text>
        </box>
        <box flexDirection="row" gap={3}>
          <text attributes={TextAttributes.DIM}><span attributes={TextAttributes.BOLD}>Ctrl+R</span> Start</text>
          <text attributes={TextAttributes.DIM}><span attributes={TextAttributes.BOLD}>Ctrl+S</span> Stop</text>
          <text attributes={TextAttributes.DIM}><span attributes={TextAttributes.BOLD}>Ctrl+O</span> Save</text>
          <text attributes={TextAttributes.DIM}><span attributes={TextAttributes.BOLD}>Ctrl+H</span> Help</text>
          <text attributes={TextAttributes.DIM}><span attributes={TextAttributes.BOLD}>Tab</span> Next</text>
          <text attributes={TextAttributes.DIM}><span attributes={TextAttributes.BOLD}>Ctrl+C</span> Quit</text>
        </box>
      </box>

      {/* Help overlay */}
      {showHelp && (
        <box position="absolute" top={3} left={2} right={2} bottom={3} border borderStyle="double" paddingX={2} paddingY={1}>
          <box>
            <text fg="#00ffff" attributes={TextAttributes.BOLD}>hping-tui — Help</text>
          </box>
          <box flexDirection="column">
            <text fg="#ffff00" attributes={TextAttributes.BOLD}>Controls</text>
            <box flexDirection="row"><box width={14}><text fg="#00ff00" attributes={TextAttributes.BOLD}>Ctrl+R</text></box><text attributes={TextAttributes.DIM}>Start hping3</text></box>
            <box flexDirection="row"><box width={14}><text fg="#00ff00" attributes={TextAttributes.BOLD}>Ctrl+S</text></box><text attributes={TextAttributes.DIM}>Stop hping3</text></box>
            <box flexDirection="row"><box width={14}><text fg="#00ff00" attributes={TextAttributes.BOLD}>Ctrl+O</text></box><text attributes={TextAttributes.DIM}>Save log</text></box>
            <box flexDirection="row"><box width={14}><text fg="#00ff00" attributes={TextAttributes.BOLD}>Ctrl+C</text></box><text attributes={TextAttributes.DIM}>Quit</text></box>
            <box flexDirection="row"><box width={14}><text fg="#00ff00" attributes={TextAttributes.BOLD}>Ctrl+H</text></box><text attributes={TextAttributes.DIM}>Toggle help</text></box>
            <text fg="#ffff00" attributes={TextAttributes.BOLD}>Navigation</text>
            <box flexDirection="row"><box width={14}><text fg="#00ff00" attributes={TextAttributes.BOLD}>Tab / ↓</text></box><text attributes={TextAttributes.DIM}>Next field</text></box>
            <box flexDirection="row"><box width={14}><text fg="#00ff00" attributes={TextAttributes.BOLD}>Shift+Tab / ↑</text></box><text attributes={TextAttributes.DIM}>Previous field</text></box>
            <text fg="#ffff00" attributes={TextAttributes.BOLD}>Protocol</text>
            <box flexDirection="row"><box width={14}><text fg="#00ff00" attributes={TextAttributes.BOLD}>Ctrl+1/2/3</text></box><text attributes={TextAttributes.DIM}>TCP / UDP / ICMP</text></box>
            <text fg="#ffff00" attributes={TextAttributes.BOLD}>Presets</text>
            <box flexDirection="row"><box width={14}><text fg="#00ff00" attributes={TextAttributes.BOLD}>F1-F6</text></box><text attributes={TextAttributes.DIM}>Load preset</text></box>
            <text fg="#ffff00" attributes={TextAttributes.BOLD}>Flags</text>
            <box flexDirection="row"><box width={14}><text fg="#00ff00" attributes={TextAttributes.BOLD}>Ctrl+Y/A/F</text></box><text attributes={TextAttributes.DIM}>Toggle SYN/ACK/FIN</text></box>
            <box flexDirection="row"><box width={14}><text fg="#00ff00" attributes={TextAttributes.BOLD}>Ctrl+D/P/U</text></box><text attributes={TextAttributes.DIM}>Toggle RST/PSH/URG</text></box>
            <text fg="#ffff00" attributes={TextAttributes.BOLD}>Options</text>
            <box flexDirection="row"><box width={14}><text fg="#00ff00" attributes={TextAttributes.BOLD}>Ctrl+G/K</text></box><text attributes={TextAttributes.DIM}>Toggle flood/fast</text></box>
            <box flexDirection="row"><box width={14}><text fg="#00ff00" attributes={TextAttributes.BOLD}>Ctrl+T/V</text></box><text attributes={TextAttributes.DIM}>Toggle trace/verbose</text></box>
            <box flexDirection="row"><box width={14}><text fg="#00ff00" attributes={TextAttributes.BOLD}>Ctrl+N/Z</text></box><text attributes={TextAttributes.DIM}>Toggle no DNS/rand src</text></box>
            <text fg="#ffff00" attributes={TextAttributes.BOLD}>Filters</text>
            <box flexDirection="row"><box width={14}><text fg="#00ff00" attributes={TextAttributes.BOLD}>Shift+R/S</text></box><text attributes={TextAttributes.DIM}>Toggle response/stats</text></box>
            <box flexDirection="row"><box width={14}><text fg="#00ff00" attributes={TextAttributes.BOLD}>Shift+E/I</text></box><text attributes={TextAttributes.DIM}>Toggle error/info</text></box>
          </box>
          <box>
            <text attributes={TextAttributes.DIM}>Press <span attributes={TextAttributes.BOLD}>Ctrl+H</span> or <span attributes={TextAttributes.BOLD}>Esc</span> to close</text>
          </box>
        </box>
      )}
    </box>
  );
}

const renderer = await createCliRenderer();
createRoot(renderer).render(<App />);
