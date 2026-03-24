import type { ConnectionStatus } from "../lib/types";

interface ConnectToggleProps {
  status: ConnectionStatus;
  onConnect: () => void;
  onDisconnect: () => void;
}

export function ConnectToggle({
  status,
  onConnect,
  onDisconnect,
}: ConnectToggleProps) {
  const isConnected = status === "connected";
  const isConnecting = status === "connecting";

  const handleClick = () => {
    if (isConnecting) return;
    if (isConnected) {
      onDisconnect();
    } else {
      onConnect();
    }
  };

  return (
    <div className="flex flex-col items-center gap-4">
      <button
        onClick={handleClick}
        disabled={isConnecting}
        className="relative w-44 h-44 rounded-full transition-all duration-300 cursor-pointer
          focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-green)]
          disabled:cursor-wait"
        style={{
          background: isConnected
            ? "radial-gradient(circle, var(--accent-green) 0%, rgba(0,255,136,0.15) 70%, transparent 100%)"
            : "transparent",
          border: isConnected
            ? "2px solid var(--accent-green)"
            : "2px solid var(--border-color)",
          boxShadow: isConnected
            ? "0 0 40px rgba(0,255,136,0.2)"
            : "none",
        }}
      >
        {isConnecting && (
          <span
            className="absolute inset-0 rounded-full border-2 border-transparent spin"
            style={{
              borderTopColor: "var(--accent-green)",
            }}
          />
        )}

        <span
          className="text-lg font-semibold"
          style={{
            color: isConnected ? "#0a0a0f" : "var(--text-primary)",
          }}
        >
          {isConnecting
            ? "Connecting..."
            : isConnected
              ? "Connected"
              : "Connect"}
        </span>
      </button>

      <p
        className="text-sm"
        style={{ color: "var(--text-secondary)" }}
      >
        {isConnecting
          ? "Establishing secure tunnel..."
          : isConnected
            ? "Encrypted tunnel active"
            : "Tap to connect"}
      </p>
    </div>
  );
}
