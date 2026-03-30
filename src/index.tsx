import { createCliRenderer, TextAttributes } from "@opentui/core";
import { createRoot, useKeyboard, useRenderer } from "@opentui/react";
import { useState, useEffect, useRef, useCallback } from "react";
import { spawn } from "child_process";

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
};

function buildHpingArgs(config: HpingConfig): string[] {
  const args: string[] = [];

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

function parseOutputLine(line: string): { type: string; content: string } {
  if (line.includes("len=") || line.includes("seq=")) {
    return { type: "response", content: line };
  }
  if (line.includes("traceroute")) {
    return { type: "traceroute", content: line };
  }
  if (
    line.includes("packets transmitted") ||
    line.includes("packets received") ||
    line.includes("round-trip")
  ) {
    return { type: "stats", content: line };
  }
  if (line.startsWith("HPING")) {
    return { type: "header", content: line };
  }
  return { type: "info", content: line };
}

function ConfigPanel({
  config,
  focusedField,
}: {
  config: HpingConfig;
  focusedField: string;
}) {
  const fields = [
    { id: "target", label: "Target" },
    { id: "port", label: "Port" },
    { id: "count", label: "Count" },
    { id: "interval", label: "Interval" },
    { id: "dataLength", label: "Data Len" },
    { id: "ttl", label: "TTL" },
    { id: "spoofIp", label: "Spoof IP" },
  ];

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

  const toggleOptions: { id: string; label: string; key: string }[] = [
    { id: "flood", label: "Flood", key: "F" },
    { id: "fast", label: "Fast", key: "f" },
    { id: "traceroute", label: "Traceroute", key: "t" },
  ];

  const getFieldValue = (id: string): string => {
    return (config as Record<string, any>)[id] ?? "";
  };

  return (
    <box flexDirection="column" flexGrow={1} paddingX={1}>
      <box marginBottom={1}>
        <text>
          <strong>Configuration</strong>
        </text>
      </box>

      <box flexDirection="column">
        {fields.map((field) => (
          <box key={field.id} flexDirection="row">
            <box width={14}>
              <text
                attributes={
                  focusedField === field.id
                    ? TextAttributes.BOLD
                    : TextAttributes.DIM
                }
              >
                {field.label}:
              </text>
            </box>
            <box flexGrow={1}>
              <text
                attributes={
                  focusedField === field.id ? TextAttributes.UNDERLINE : undefined
                }
              >
                {getFieldValue(field.id)}
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
        <text attributes={TextAttributes.DIM}>TCP Flags:</text>
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
      <box flexDirection="row" gap={2}>
        {toggleOptions.map((t) => (
          <box key={t.id}>
            <text
              attributes={
                (config as Record<string, any>)[t.id] ? TextAttributes.BOLD : TextAttributes.DIM
              }
            >
              [{t.key}] {t.label}
            </text>
          </box>
        ))}
      </box>
    </box>
  );
}

function OutputDisplay({
  lines,
  stats,
  isRunning,
}: {
  lines: { type: string; content: string }[];
  stats: HpingStats | null;
  isRunning: boolean;
}) {
  const getLineColor = (type: string): string => {
    switch (type) {
      case "response":
        return "#00ff00";
      case "stats":
        return "#ffff00";
      case "header":
        return "#00ffff";
      case "error":
        return "#ff0000";
      case "traceroute":
        return "#ff00ff";
      default:
        return "#cccccc";
    }
  };

  return (
    <box flexDirection="column" flexGrow={1} paddingX={1}>
      <box marginBottom={1} flexDirection="row" justifyContent="space-between">
        <text>
          <strong>Output</strong>
        </text>
        <text>
          {isRunning ? (
            <span fg="#00ff00">Running</span>
          ) : (
            <span fg="#888888">Stopped</span>
          )}
        </text>
      </box>

      <box flexDirection="column" flexGrow={1} border borderStyle="single">
        <scrollbox flexGrow={1}>
          {lines.slice(-200).map((line, i) => (
            <text key={i} fg={getLineColor(line.type)}>
              {line.content}
            </text>
          ))}
          {lines.length === 0 && (
            <text attributes={TextAttributes.DIM}>
              Press Ctrl+R to start hping3...
            </text>
          )}
        </scrollbox>
      </box>

      {stats && (
        <box marginTop={1} flexDirection="row" gap={4}>
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
              <span fg="#00ffff">RTT avg:</span> {stats.rttAvg}
            </text>
          )}
        </box>
      )}
    </box>
  );
}

function StatusBar({
  command,
  error,
}: {
  command: string;
  error: string | null;
}) {
  return (
    <box
      flexDirection="column"
      borderTop
      borderStyle="single"
      paddingX={1}
      paddingY={0}
    >
      <box flexDirection="row" justifyContent="space-between">
        <text attributes={TextAttributes.DIM}>
          Command: <span fg="#00ff00">{command}</span>
        </text>
      </box>
      {error && (
        <box>
          <text fg="#ff0000">Error: {error}</text>
        </box>
      )}
      <box flexDirection="row" gap={4}>
        <text attributes={TextAttributes.DIM}>
          <strong>Ctrl+R</strong> Start
        </text>
        <text attributes={TextAttributes.DIM}>
          <strong>Ctrl+S</strong> Stop
        </text>
        <text attributes={TextAttributes.DIM}>
          <strong>Ctrl+C</strong> Quit
        </text>
        <text attributes={TextAttributes.DIM}>
          <strong>Tab</strong> Next field
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
        <strong>hping3</strong>
      </text>
      <text attributes={TextAttributes.DIM}> - Network Packet Analyzer</text>
    </box>
  );
}

function App() {
  const [config, setConfig] = useState<HpingConfig>(DEFAULT_CONFIG);
  const [outputLines, setOutputLines] = useState<
    { type: string; content: string }[]
  >([]);
  const [stats, setStats] = useState<HpingStats | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [focusedField, setFocusedField] = useState("target");
  const processRef = useRef<any>(null);
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
      { type: "header", content: `$ ${command}` },
      { type: "info", content: `Starting hping3 to ${config.target}...` },
    ]);

    try {
      const proc = spawn("sudo", ["hping3", ...args], {
        shell: false,
      });

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
        const parsedLines = lines.map((l) => ({ type: "error", content: l }));
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
          },
        ]);
      });

      proc.on("error", (err: Error) => {
        setIsRunning(false);
        processRef.current = null;
        setError(`Failed to start hping3: ${err.message}`);
        setOutputLines((prev) => [
          ...prev,
          { type: "error", content: `Error: ${err.message}` },
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
        { type: "info", content: "Process stopped by user" },
      ]);
    }
  }, []);

  useKeyboard((key) => {
    if (key.ctrl && key.name === "c") {
      stopHping();
      renderer.destroy();
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

    if (key.name === "tab") {
      const fields = [
        "target",
        "port",
        "count",
        "interval",
        "dataLength",
        "ttl",
        "spoofIp",
      ];
      const idx = fields.indexOf(focusedField);
      const nextIdx = (idx + 1) % fields.length;
      if (fields[nextIdx]) setFocusedField(fields[nextIdx]);
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
      const fields = [
        "target",
        "port",
        "count",
        "interval",
        "dataLength",
        "ttl",
        "spoofIp",
      ];
      const idx = fields.indexOf(focusedField);
      const nextIdx = (idx + 1) % fields.length;
      if (fields[nextIdx]) setFocusedField(fields[nextIdx]);
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

    if (key.name === "F") {
      setConfig((prev) => ({ ...prev, flood: !prev.flood }));
      return;
    }
    if (key.shift && key.name === "t") {
      setConfig((prev) => ({ ...prev, traceroute: !prev.traceroute }));
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
    };
  }, []);

  const commandString = buildCommandString(config);

  return (
    <box flexDirection="column" flexGrow={1}>
      <Header />

      <box flexDirection="row" flexGrow={1}>
        <box width={40} border borderStyle="single" flexDirection="column">
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
          />
        </box>
      </box>

      <StatusBar
        command={commandString}
        error={error}
      />
    </box>
  );
}

const renderer = await createCliRenderer();
createRoot(renderer).render(<App />);
