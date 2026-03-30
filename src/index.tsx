import { createCliRenderer, TextAttributes } from "@opentui/core";
import { createRoot, useKeyboard, useRenderer } from "@opentui/react";
import { useState, useEffect, useRef, useCallback } from "react";
import { spawn, ChildProcess } from "child_process";
import { writeFileSync, mkdirSync } from "fs";
import { homedir } from "os";
import { join } from "path";

type Protocol = "tcp" | "udp" | "icmp";

interface HpingConfig {
  target: string;
  protocol: Protocol;
  port: string;
  count: string;
  interval: string;
  flags: {
    syn: boolean;
    ack: boolean;
    fin: boolean;
    rst: boolean;
    psh: boolean;
    urg: boolean;
  };
  dataLength: string;
  ttl: string;
  flood: boolean;
  fast: boolean;
  traceroute: boolean;
  spoofIp: string;
  verbose: boolean;
  noDns: boolean;
  windowSize: string;
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
  count: "10",
  interval: "1",
  flags: {
    syn: true,
    ack: false,
    fin: false,
    rst: false,
    psh: false,
    urg: false,
  },
  dataLength: "0",
  ttl: "64",
  flood: false,
  fast: false,
  traceroute: false,
  spoofIp: "",
  verbose: false,
  noDns: false,
  windowSize: "",
};

const PRESETS: { name: string; icon: string; config: Partial<HpingConfig> }[] = [
  {
    name: "SYN Scan",
    icon: "S",
    config: { protocol: "tcp", flags: { syn: true, ack: false, fin: false, rst: false, psh: false, urg: false }, port: "80", count: "10" },
  },
  {
    name: "Firewall Test",
    icon: "F",
    config: { protocol: "tcp", flags: { syn: true, ack: true, fin: false, rst: false, psh: false, urg: false }, port: "443", count: "20" },
  },
  {
    name: "ICMP Ping",
    icon: "I",
    config: { protocol: "icmp", flags: { syn: false, ack: false, fin: false, rst: false, psh: false, urg: false }, port: "", count: "10" },
  },
  {
    name: "Traceroute",
    icon: "T",
    config: { protocol: "tcp", traceroute: true, flags: { syn: true, ack: false, fin: false, rst: false, psh: false, urg: false }, port: "80", count: "30" },
  },
  {
    name: "UDP Test",
    icon: "U",
    config: { protocol: "udp", flags: { syn: false, ack: false, fin: false, rst: false, psh: false, urg: false }, port: "53", count: "10" },
  },
  {
    name: "XMAS Scan",
    icon: "X",
    config: { protocol: "tcp", flags: { syn: false, ack: false, fin: true, rst: false, psh: true, urg: true }, port: "80", count: "5" },
  },
];

const FIELD_ORDER = ["target", "port", "count", "interval", "dataLength", "ttl", "windowSize", "spoofIp"] as const;

function buildHpingArgs(config: HpingConfig): string[] {
  const args: string[] = [];

  if (config.noDns) args.push("-n");
  if (config.verbose) args.push("-V");

  if (config.protocol === "icmp") args.push("-1");
  else if (config.protocol === "udp") args.push("-2");

  if (config.protocol !== "icmp" && config.port) {
    args.push("-p", config.port);
  }

  if (config.count) args.push("-c", config.count);
  if (config.interval) args.push("-i", config.interval);
  if (config.dataLength && parseInt(config.dataLength) > 0)
    args.push("-d", config.dataLength);
  if (config.ttl) args.push("--ttl", config.ttl);
  if (config.windowSize && parseInt(config.windowSize) > 0)
    args.push("--win", config.windowSize);

  if (config.flags.syn) args.push("-S");
  if (config.flags.ack) args.push("-A");
  if (config.flags.fin) args.push("-F");
  if (config.flags.rst) args.push("-R");
  if (config.flags.psh) args.push("-P");
  if (config.flags.urg) args.push("-U");

  if (config.flood) args.push("--flood");
  if (config.fast) args.push("--fast");
  if (config.traceroute) args.push("--traceroute");
  if (config.spoofIp) args.push("-a", config.spoofIp);

  args.push(config.target);
  return args;
}

function buildCommandString(config: HpingConfig): string {
  const args = buildHpingArgs(config);
  return `hping3 ${args.join(" ")}`;
}

function parseStatsLine(line: string): Partial<HpingStats> | null {
  const stats: Partial<HpingStats> = {};

  const sentMatch = line.match(/(\d+)\s+packets?\s+transmitted/);
  if (sentMatch && sentMatch[1]) stats.packetsSent = parseInt(sentMatch[1]);

  const recvMatch = line.match(/(\d+)\s+packets?\s+received/);
  if (recvMatch && recvMatch[1]) stats.packetsReceived = parseInt(recvMatch[1]);

  const lossMatch = line.match(/([\d.]+)%\s+packets?\s+lost/);
  if (lossMatch && lossMatch[1]) stats.packetLoss = lossMatch[1] + "%";

  const rttMatch = line.match(
    /round-trip\s+min\/avg\/max\s+=\s+([\d.]+)\/([\d.]+)\/([\d.]+)\/?([\d.]*)\s+ms/
  );
  if (rttMatch && rttMatch[1] && rttMatch[2] && rttMatch[3]) {
    stats.rttMin = rttMatch[1] + " ms";
    stats.rttAvg = rttMatch[2] + " ms";
    stats.rttMax = rttMatch[3] + " ms";
    if (rttMatch[4]) stats.rttMdev = rttMatch[4] + " ms";
  }

  return Object.keys(stats).length > 0 ? stats : null;
}

function parseOutputLine(line: string): OutputLine {
  let type = "info";
  if (line.includes("len=") || line.includes("seq=")) type = "response";
  else if (line.includes("traceroute") || line.includes("HOP")) type = "traceroute";
  else if (
    line.includes("packets transmitted") ||
    line.includes("packets received") ||
    line.includes("round-trip")
  ) type = "stats";
  else if (line.startsWith("HPING")) type = "header";
  else if (
    line.toLowerCase().includes("error") ||
    line.toLowerCase().includes("fail") ||
    line.toLowerCase().includes("denied") ||
    line.includes("can't")
  ) type = "error";

  return {
    type,
    content: line,
    timestamp: new Date().toLocaleTimeString(),
  };
}

function getLineColor(type: string): string {
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
  const num = parseFloat(loss);
  if (isNaN(num)) return "";
  const filled = Math.round((num / 100) * 10);
  const empty = 10 - filled;
  return "█".repeat(filled) + "░".repeat(empty);
}

function PresetBar({ onSelect }: { onSelect: (preset: Partial<HpingConfig>) => void }) {
  return (
    <box flexDirection="row" gap={1} paddingX={1}>
      {PRESETS.map((p, i) => (
        <box key={p.name}>
          <text attributes={TextAttributes.DIM}>
            [{i + 1}]
          </text>
          <text> {p.icon} {p.name} </text>
        </box>
      ))}
    </box>
  );
}

function ConfigPanel({
  config,
  focusedField,
}: {
  config: HpingConfig;
  focusedField: string;
}) {
  const fieldLabels: Record<string, string> = {
    target: "Target",
    port: "Port",
    count: "Count",
    interval: "Interval",
    dataLength: "Data Len",
    ttl: "TTL",
    windowSize: "Win Size",
    spoofIp: "Spoof IP",
  };

  const getFieldValue = (id: string): string => {
    return (config as Record<string, any>)[id] ?? "";
  };

  const protocols: { id: Protocol; label: string; key: string }[] = [
    { id: "tcp", label: "TCP", key: "1" },
    { id: "udp", label: "UDP", key: "2" },
    { id: "icmp", label: "ICMP", key: "3" },
  ];

  const flagOptions: { id: keyof HpingConfig["flags"]; label: string; key: string }[] = [
    { id: "syn", label: "SYN", key: "s" },
    { id: "ack", label: "ACK", key: "a" },
    { id: "fin", label: "FIN", key: "f" },
    { id: "rst", label: "RST", key: "r" },
    { id: "psh", label: "PSH", key: "p" },
    { id: "urg", label: "URG", key: "u" },
  ];

  return (
    <box flexDirection="column" flexGrow={1} paddingX={1}>
      <box marginBottom={1}>
        <text>
          <strong>Configuration</strong>
        </text>
      </box>

      <box flexDirection="column">
        {FIELD_ORDER.map((fieldId) => (
          <box key={fieldId} flexDirection="row">
            <box width={10}>
              <text
                attributes={
                  focusedField === fieldId
                    ? TextAttributes.BOLD
                    : TextAttributes.DIM
                }
              >
                {fieldLabels[fieldId]}:
              </text>
            </box>
            <box flexGrow={1}>
              <text
                attributes={
                  focusedField === fieldId ? TextAttributes.UNDERLINE : undefined
                }
              >
                {getFieldValue(fieldId)}
              </text>
            </box>
          </box>
        ))}
      </box>

      <box marginTop={1} marginBottom={1}>
        <text attributes={TextAttributes.DIM}>Protocol:</text>
      </box>
      <box flexDirection="row" gap={2} marginBottom={1}>
        {protocols.map((p) => (
          <box key={p.id}>
            <text
              attributes={
                config.protocol === p.id
                  ? TextAttributes.BOLD
                  : TextAttributes.DIM
              }
            >
              [{p.key}] {p.label}
            </text>
          </box>
        ))}
      </box>

      <box marginBottom={1}>
        <text attributes={TextAttributes.DIM}>Flags:</text>
      </box>
      <box flexDirection="row" gap={2} marginBottom={1}>
        {flagOptions.map((f) => (
          <box key={f.id}>
            <text
              attributes={
                config.flags[f.id] ? TextAttributes.BOLD : TextAttributes.DIM
              }
            >
              [{f.key}] {f.label}
            </text>
          </box>
        ))}
      </box>

      <box marginBottom={1}>
        <text attributes={TextAttributes.DIM}>Options:</text>
      </box>
      <box flexDirection="column" gap={0}>
        <box flexDirection="row">
          <text
            attributes={config.flood ? TextAttributes.BOLD : TextAttributes.DIM}
          >
            [Shift+F] Flood
          </text>
          <box width={4} />
          <text
            attributes={config.fast ? TextAttributes.BOLD : TextAttributes.DIM}
          >
            [Shift+A] Fast
          </text>
        </box>
        <box flexDirection="row">
          <text
            attributes={config.traceroute ? TextAttributes.BOLD : TextAttributes.DIM}
          >
            [Shift+T] Traceroute
          </text>
          <box width={4} />
          <text
            attributes={config.verbose ? TextAttributes.BOLD : TextAttributes.DIM}
          >
            [Shift+V] Verbose
          </text>
        </box>
        <box flexDirection="row">
          <text
            attributes={config.noDns ? TextAttributes.BOLD : TextAttributes.DIM}
          >
            [Shift+N] No DNS
          </text>
        </box>
      </box>
    </box>
  );
}

function OutputDisplay({
  lines,
  stats,
  isRunning,
  filter,
}: {
  lines: OutputLine[];
  stats: HpingStats | null;
  isRunning: boolean;
  filter: Set<string>;
}) {
  const filteredLines = lines.filter((l) => filter.has(l.type));
  const displayLines = filteredLines.slice(-300);

  return (
    <box flexDirection="column" flexGrow={1} paddingX={1}>
      <box marginBottom={1} flexDirection="row" justifyContent="space-between">
        <text>
          <strong>Output</strong>
          <text attributes={TextAttributes.DIM}> ({filteredLines.length} lines)</text>
        </text>
        <text>
          {isRunning ? (
            <span fg="#00ff00">● Running</span>
          ) : (
            <span fg="#888888">○ Stopped</span>
          )}
        </text>
      </box>

      <box flexDirection="column" flexGrow={1} border borderStyle="single">
        <scrollbox flexGrow={1}>
          {displayLines.map((line, i) => (
            <text key={i} fg={getLineColor(line.type)}>
              <span fg="#555555">[{line.timestamp}]</span> {line.content}
            </text>
          ))}
          {displayLines.length === 0 && (
            <text attributes={TextAttributes.DIM}>
              Press Ctrl+R to start hping3...
            </text>
          )}
        </scrollbox>
      </box>

      {stats && (
        <box marginTop={1} flexDirection="column" gap={0}>
          <box flexDirection="row" gap={4}>
            <text>
              <span fg="#00ffff">Sent:</span> {stats.packetsSent}
            </text>
            <text>
              <span fg="#00ffff">Recv:</span> {stats.packetsReceived}
            </text>
            <text>
              <span fg="#00ffff">Loss:</span> {stats.packetLoss}
            </text>
            {stats.rttAvg && (
              <text>
                <span fg="#00ffff">RTT:</span> {stats.rttAvg}
              </text>
            )}
          </box>
          {stats.packetLoss && (
            <box>
              <text fg="#ff8800">
                {lossBar(stats.packetLoss)}
              </text>
            </box>
          )}
        </box>
      )}
    </box>
  );
}

function StatusBar({
  command,
  error,
  focusedField,
}: {
  command: string;
  error: string | null;
  focusedField: string;
}) {
  return (
    <box
      flexDirection="column"
      borderTop
      borderStyle="single"
      paddingX={1}
      paddingY={0}
    >
      {error && (
        <box>
          <text fg="#ff4444">⚠ {error}</text>
        </box>
      )}
      <box flexDirection="row" justifyContent="space-between">
        <text attributes={TextAttributes.DIM}>
          <span fg="#00ff00">{command}</span>
        </text>
        <text attributes={TextAttributes.DIM}>
          Editing: <strong>{focusedField}</strong>
        </text>
      </box>
      <box flexDirection="row" gap={3}>
        <text attributes={TextAttributes.DIM}>
          <strong>Ctrl+R</strong> Start
        </text>
        <text attributes={TextAttributes.DIM}>
          <strong>Ctrl+S</strong> Stop
        </text>
        <text attributes={TextAttributes.DIM}>
          <strong>Ctrl+O</strong> Save log
        </text>
        <text attributes={TextAttributes.DIM}>
          <strong>Ctrl+H</strong> Help
        </text>
        <text attributes={TextAttributes.DIM}>
          <strong>Tab</strong> Field
        </text>
        <text attributes={TextAttributes.DIM}>
          <strong>Ctrl+C</strong> Quit
        </text>
      </box>
    </box>
  );
}

function Header() {
  return (
    <box
      flexDirection="row"
      alignItems="center"
      paddingX={1}
      paddingY={0}
      borderBottom
      borderStyle="single"
    >
      <text fg="#00ffff">
        <strong>hping-tui</strong>
      </text>
      <text attributes={TextAttributes.DIM}> — Interactive hping3 Terminal UI</text>
      <box flexGrow={1} />
      <text fg="#00ffff">v1.0.0</text>
    </box>
  );
}

function HelpOverlay() {
  const helpItems = [
    { section: "Controls", items: [
      ["Ctrl+R", "Start / restart hping3"],
      ["Ctrl+S", "Stop running process"],
      ["Ctrl+O", "Save output to log file"],
      ["Ctrl+C", "Quit application"],
      ["Ctrl+H", "Toggle this help screen"],
      ["Tab", "Cycle through input fields"],
      ["Enter", "Confirm field, move to next"],
      ["Backspace", "Delete character"],
    ]},
    { section: "Protocol", items: [
      ["Ctrl+1", "TCP mode"],
      ["Ctrl+2", "UDP mode"],
      ["Ctrl+3", "ICMP mode"],
    ]},
    { section: "TCP Flags", items: [
      ["s", "Toggle SYN flag"],
      ["a", "Toggle ACK flag"],
      ["f", "Toggle FIN flag"],
      ["r", "Toggle RST flag"],
      ["p", "Toggle PSH flag"],
      ["u", "Toggle URG flag"],
    ]},
    { section: "Options", items: [
      ["Shift+F", "Toggle flood mode"],
      ["Shift+A", "Toggle fast mode"],
      ["Shift+T", "Toggle traceroute"],
      ["Shift+V", "Toggle verbose"],
      ["Shift+N", "Toggle no DNS resolution"],
    ]},
    { section: "Presets", items: [
      ["1-6", "Load preset configuration"],
    ]},
    { section: "Filters", items: [
      ["Shift+R", "Toggle response lines"],
      ["Shift+S", "Toggle stats lines"],
      ["Shift+E", "Toggle error lines"],
      ["Shift+I", "Toggle info lines"],
    ]},
  ];

  return (
    <box
      flexDirection="column"
      border
      borderStyle="double"
      paddingX={2}
      paddingY={1}
    >
      <box marginBottom={1}>
        <text fg="#00ffff">
          <strong>hping-tui — Help</strong>
        </text>
      </box>
      {helpItems.map((section) => (
        <box key={section.section} flexDirection="column" marginBottom={1}>
          <text fg="#ffff00">
            <strong>{section.section}</strong>
          </text>
          {section.items.map(([key, desc]) => (
            <box key={key} flexDirection="row">
              <box width={14}>
                <text fg="#00ff00">
                  <strong>{key}</strong>
                </text>
              </box>
              <text attributes={TextAttributes.DIM}>{desc}</text>
            </box>
          ))}
        </box>
      ))}
      <box marginTop={1}>
        <text attributes={TextAttributes.DIM}>
          Press <strong>Ctrl+H</strong> or <strong>Esc</strong> to close
        </text>
      </box>
    </box>
  );
}

function loadConfig(): HpingConfig {
  try {
    const configPath = join(homedir(), ".hping-tui", "config.json");
    const data = require("fs").readFileSync(configPath, "utf-8");
    return { ...DEFAULT_CONFIG, ...JSON.parse(data) };
  } catch {
    return { ...DEFAULT_CONFIG };
  }
}

function saveConfig(config: HpingConfig) {
  try {
    const configDir = join(homedir(), ".hping-tui");
    mkdirSync(configDir, { recursive: true });
    writeFileSync(join(configDir, "config.json"), JSON.stringify(config, null, 2));
  } catch {
    // ignore
  }
}

function App() {
  const [config, setConfig] = useState<HpingConfig>(loadConfig);
  const [outputLines, setOutputLines] = useState<OutputLine[]>([]);
  const [stats, setStats] = useState<HpingStats | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [focusedField, setFocusedField] = useState("target");
  const [showHelp, setShowHelp] = useState(false);
  const [filter, setFilter] = useState<Set<string>>(
    new Set(["response", "stats", "header", "info", "traceroute", "error"])
  );
  const processRef = useRef<ChildProcess | null>(null);
  const renderer = useRenderer();

  const runHping = useCallback(() => {
    if (!config.target) {
      setError("Target host is required");
      return;
    }

    if (processRef.current) {
      processRef.current.kill("SIGTERM");
    }

    setError(null);
    setOutputLines([]);
    setStats(null);

    const args = buildHpingArgs(config);
    const command = `hping3 ${args.join(" ")}`;

    setOutputLines([
      { type: "header", content: `$ ${command}`, timestamp: new Date().toLocaleTimeString() },
      { type: "info", content: `Starting hping3 to ${config.target}...`, timestamp: new Date().toLocaleTimeString() },
    ]);

    try {
      const proc = spawn("sudo", ["hping3", ...args], { shell: false });

      processRef.current = proc;
      setIsRunning(true);

      proc.stdout.on("data", (data: Buffer) => {
        const text = data.toString();
        const lines = text.split("\n").filter((l) => l.trim());

        const parsedLines = lines.map(parseOutputLine);
        setOutputLines((prev) => [...prev, ...parsedLines]);

        for (const line of lines) {
          const parsed = parseStatsLine(line);
          if (parsed) {
            setStats((prev) => ({ ...prev, ...parsed } as HpingStats));
          }
        }
      });

      proc.stderr.on("data", (data: Buffer) => {
        const text = data.toString();
        const lines = text.split("\n").filter((l) => l.trim());
        const parsedLines = lines.map((l) => ({
          type: "error" as const,
          content: l,
          timestamp: new Date().toLocaleTimeString(),
        }));
        setOutputLines((prev) => [...prev, ...parsedLines]);
      });

      proc.on("close", (code: number) => {
        setIsRunning(false);
        processRef.current = null;
        setOutputLines((prev) => [
          ...prev,
          {
            type: "info",
            content: `Process exited with code ${code}`,
            timestamp: new Date().toLocaleTimeString(),
          },
        ]);
      });

      proc.on("error", (err: Error) => {
        setIsRunning(false);
        processRef.current = null;
        setError(`Failed to start hping3: ${err.message}`);
        setOutputLines((prev) => [
          ...prev,
          { type: "error", content: `Error: ${err.message}`, timestamp: new Date().toLocaleTimeString() },
        ]);
      });
    } catch (err: any) {
      setError(`Failed to spawn process: ${err.message}`);
      setIsRunning(false);
    }
  }, [config]);

  const stopHping = useCallback(() => {
    if (processRef.current) {
      processRef.current.kill("SIGTERM");
      processRef.current = null;
      setIsRunning(false);
      setOutputLines((prev) => [
        ...prev,
        { type: "info", content: "Process stopped by user", timestamp: new Date().toLocaleTimeString() },
      ]);
    }
  }, []);

  const saveLog = useCallback(() => {
    try {
      const logDir = join(homedir(), ".hping-tui");
      mkdirSync(logDir, { recursive: true });
      const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
      const logPath = join(logDir, `hping-${timestamp}.log`);
      const content = outputLines.map((l) => `[${l.timestamp}] ${l.content}`).join("\n");
      writeFileSync(logPath, content);
      setError(null);
      setOutputLines((prev) => [
        ...prev,
        { type: "info", content: `Log saved to ${logPath}`, timestamp: new Date().toLocaleTimeString() },
      ]);
    } catch (err: any) {
      setError(`Failed to save log: ${err.message}`);
    }
  }, [outputLines]);

  useKeyboard((key) => {
    if (showHelp && (key.ctrl && key.name === "h" || key.name === "escape")) {
      setShowHelp(false);
      return;
    }

    if (key.ctrl && key.name === "c") {
      stopHping();
      saveConfig(config);
      renderer.destroy();
      return;
    }

    if (key.ctrl && key.name === "h") {
      setShowHelp((v) => !v);
      return;
    }

    if (key.ctrl && key.name === "r") {
      runHping();
      return;
    }

    if (key.ctrl && key.name === "s") {
      stopHping();
      return;
    }

    if (key.ctrl && key.name === "o") {
      saveLog();
      return;
    }

    if (key.name === "tab") {
      const idx = FIELD_ORDER.indexOf(focusedField as any);
      const nextIdx = (idx + 1) % FIELD_ORDER.length;
      setFocusedField(FIELD_ORDER[nextIdx]);
      return;
    }

    if (key.name === "backspace") {
      setConfig((prev) => {
        const val = ((prev as Record<string, any>)[focusedField] as string) || "";
        return { ...prev, [focusedField]: val.slice(0, -1) };
      });
      return;
    }

    if (key.name === "enter") {
      const idx = FIELD_ORDER.indexOf(focusedField as any);
      const nextIdx = (idx + 1) % FIELD_ORDER.length;
      setFocusedField(FIELD_ORDER[nextIdx]);
      return;
    }

    if (key.ctrl && key.name === "1") {
      setConfig((prev) => ({ ...prev, protocol: "tcp" }));
      return;
    }
    if (key.ctrl && key.name === "2") {
      setConfig((prev) => ({ ...prev, protocol: "udp" }));
      return;
    }
    if (key.ctrl && key.name === "3") {
      setConfig((prev) => ({ ...prev, protocol: "icmp" }));
      return;
    }

    if (key.name === "s" && !key.ctrl) {
      setConfig((prev) => ({
        ...prev,
        flags: { ...prev.flags, syn: !prev.flags.syn },
      }));
      return;
    }
    if (key.name === "a" && !key.ctrl) {
      setConfig((prev) => ({
        ...prev,
        flags: { ...prev.flags, ack: !prev.flags.ack },
      }));
      return;
    }
    if (key.name === "f" && !key.ctrl) {
      setConfig((prev) => ({
        ...prev,
        flags: { ...prev.flags, fin: !prev.flags.fin },
      }));
      return;
    }
    if (key.name === "r" && !key.ctrl) {
      setConfig((prev) => ({
        ...prev,
        flags: { ...prev.flags, rst: !prev.flags.rst },
      }));
      return;
    }
    if (key.name === "p" && !key.ctrl) {
      setConfig((prev) => ({
        ...prev,
        flags: { ...prev.flags, psh: !prev.flags.psh },
      }));
      return;
    }
    if (key.name === "u" && !key.ctrl) {
      setConfig((prev) => ({
        ...prev,
        flags: { ...prev.flags, urg: !prev.flags.urg },
      }));
      return;
    }

    if (key.shift && key.name === "f") {
      setConfig((prev) => ({ ...prev, flood: !prev.flood }));
      return;
    }
    if (key.shift && key.name === "a") {
      setConfig((prev) => ({ ...prev, fast: !prev.fast }));
      return;
    }
    if (key.shift && key.name === "t") {
      setConfig((prev) => ({ ...prev, traceroute: !prev.traceroute }));
      return;
    }
    if (key.shift && key.name === "v") {
      setConfig((prev) => ({ ...prev, verbose: !prev.verbose }));
      return;
    }
    if (key.shift && key.name === "n") {
      setConfig((prev) => ({ ...prev, noDns: !prev.noDns }));
      return;
    }

    if (key.shift && key.name === "r") {
      setFilter((prev) => {
        const next = new Set(prev);
        if (next.has("response")) next.delete("response"); else next.add("response");
        return next;
      });
      return;
    }
    if (key.shift && key.name === "s") {
      setFilter((prev) => {
        const next = new Set(prev);
        if (next.has("stats")) next.delete("stats"); else next.add("stats");
        return next;
      });
      return;
    }
    if (key.shift && key.name === "e") {
      setFilter((prev) => {
        const next = new Set(prev);
        if (next.has("error")) next.delete("error"); else next.add("error");
        return next;
      });
      return;
    }
    if (key.shift && key.name === "i") {
      setFilter((prev) => {
        const next = new Set(prev);
        if (next.has("info")) next.delete("info"); else next.add("info");
        if (next.has("header")) next.delete("header"); else next.add("header");
        return next;
      });
      return;
    }

    if (key.name >= "1" && key.name <= "6" && !key.ctrl && !key.shift) {
      const presetIdx = parseInt(key.name) - 1;
      if (PRESETS[presetIdx]) {
        setConfig((prev) => ({ ...prev, ...PRESETS[presetIdx].config }));
      }
      return;
    }

    if (key.sequence && key.sequence.length === 1 && focusedField) {
      setConfig((prev) => {
        const val = ((prev as Record<string, any>)[focusedField] as string) || "";
        return { ...prev, [focusedField]: val + key.sequence };
      });
      return;
    }
  });

  useEffect(() => {
    return () => {
      if (processRef.current) {
        processRef.current.kill("SIGTERM");
      }
      saveConfig(config);
    };
  }, []);

  useEffect(() => {
    saveConfig(config);
  }, [config]);

  const commandString = buildCommandString(config);

  return (
    <box flexDirection="column" flexGrow={1}>
      <Header />
      <PresetBar onSelect={(preset) => setConfig((prev) => ({ ...prev, ...preset }))} />

      <box flexDirection="row" flexGrow={1}>
        <box width={36} border borderStyle="single" flexDirection="column">
          <ConfigPanel
            config={config}
            focusedField={focusedField}
          />
        </box>

        <box flexGrow={1} flexDirection="column">
          <OutputDisplay
            lines={outputLines}
            stats={stats}
            isRunning={isRunning}
            filter={filter}
          />
        </box>
      </box>

      <StatusBar
        command={commandString}
        error={error}
        focusedField={focusedField}
      />

      {showHelp && (
        <box
          position="absolute"
          top={3}
          left={2}
          right={2}
          bottom={3}
        >
          <HelpOverlay />
        </box>
      )}
    </box>
  );
}

const renderer = await createCliRenderer();
createRoot(renderer).render(<App />);
