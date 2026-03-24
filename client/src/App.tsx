import { useState, type ReactNode } from "react";
import { ConnectToggle } from "./components/ConnectToggle";
import { CircuitMap } from "./components/CircuitMap";
import { NodeBrowser } from "./components/NodeBrowser";
import { SessionCost } from "./components/SessionCost";
import { GasMonitor } from "./components/GasMonitor";
import { Settings } from "./components/Settings";
import { useCircuit } from "./hooks/useCircuit";
import { useNodes } from "./hooks/useNodes";
import { useSession } from "./hooks/useSession";
import { useGas } from "./hooks/useGas";

function Collapsible({ title, children }: { title: string; children: ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <section
      className="rounded-lg overflow-hidden"
      style={{ background: "var(--card-bg)", border: "1px solid var(--border-color)" }}
    >
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center justify-between px-4 py-3 cursor-pointer"
        style={{ background: "transparent", border: "none", color: "var(--text-primary)" }}
      >
        <span className="text-sm font-semibold">{title}</span>
        <span
          className="text-xs transition-transform duration-200"
          style={{ color: "var(--text-secondary)", transform: open ? "rotate(180deg)" : "rotate(0deg)" }}
        >
          &#9662;
        </span>
      </button>
      {open && <div className="px-4 pb-4">{children}</div>}
    </section>
  );
}

function App() {
  const { status, error: connectError, circuit, rotationCount, connect, disconnect } = useCircuit();
  const { nodes, loading: nodesLoading, error: nodesError, refresh } = useNodes();
  const { session, loading: sessionLoading } = useSession(status);
  const { gasPrice, level: gasLevel } = useGas();

  const isConnected = status === "connected";

  return (
    <div className="min-h-screen flex flex-col" style={{ background: "var(--bg-dark)" }}>
      <header
        className="flex items-center justify-between px-5 py-3 shrink-0"
        style={{ borderBottom: "1px solid var(--border-color)" }}
      >
        <h1 className="text-base font-bold tracking-wide" style={{ color: "var(--text-primary)" }}>
          ShieldNode
        </h1>
        <div className="flex items-center gap-2">
          <span
            className={`w-2.5 h-2.5 rounded-full ${isConnected ? "pulse-green" : ""}`}
            style={{ background: isConnected ? "var(--accent-green)" : "var(--accent-red)" }}
          />
          <span className="text-xs" style={{ color: "var(--text-secondary)" }}>
            {status === "connecting" ? "Connecting" : isConnected ? "Protected" : "Unprotected"}
          </span>
        </div>
      </header>

      <main className="flex-1 overflow-y-auto px-5 py-6">
        <div className="max-w-lg mx-auto flex flex-col gap-5">
          <section className="flex flex-col items-center gap-2 py-6">
            <ConnectToggle status={status} onConnect={connect} onDisconnect={disconnect} />
            {connectError && (
              <p className="text-xs" style={{ color: "var(--accent-red)" }}>{connectError}</p>
            )}
          </section>

          <CircuitMap status={status} circuit={circuit} rotationCount={rotationCount} />

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <SessionCost session={session} loading={sessionLoading} />
            <GasMonitor gasPrice={gasPrice} level={gasLevel} />
          </div>

          <Collapsible title="Node Browser">
            <NodeBrowser nodes={nodes} loading={nodesLoading} error={nodesError} onRefresh={refresh} />
          </Collapsible>

          <Collapsible title="Settings">
            <Settings />
          </Collapsible>
        </div>
      </main>
    </div>
  );
}

export default App;
