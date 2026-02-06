import { useSocket, CONNECTION_STATES } from '../context/SocketContext';

function getStatusConfig(connectionState, reconnectAttempt) {
  switch (connectionState) {
    case CONNECTION_STATES.CONNECTED:
      return {
        dotColor: 'bg-primary-500',
        glowColor: 'shadow-[0_0_6px_rgba(176,125,79,0.4)]',
        textColor: 'text-zinc-400',
        text: 'Connected',
        animate: true,
      };
    case CONNECTION_STATES.RECONNECTING:
      return {
        dotColor: 'bg-amber-500',
        glowColor: 'shadow-[0_0_6px_rgba(245,158,11,0.4)]',
        textColor: 'text-amber-400',
        text: reconnectAttempt > 1
          ? `Reconnecting (${reconnectAttempt})...`
          : 'Reconnecting...',
        animate: true,
      };
    case CONNECTION_STATES.DISCONNECTED:
    default:
      return {
        dotColor: 'bg-red-500',
        glowColor: '',
        textColor: 'text-red-400',
        text: 'Disconnected',
        animate: false,
      };
  }
}

function getAriaLabel(connectionState, reconnectAttempt) {
  switch (connectionState) {
    case CONNECTION_STATES.CONNECTED:
      return 'WebSocket connection status: Connected';
    case CONNECTION_STATES.RECONNECTING:
      if (reconnectAttempt > 1) {
        return `WebSocket connection status: Reconnecting, attempt ${reconnectAttempt}`;
      }
      return 'WebSocket connection status: Reconnecting';
    case CONNECTION_STATES.DISCONNECTED:
    default:
      return 'WebSocket connection status: Disconnected';
  }
}

function ConnectionStatus() {
  const { connectionState, reconnectAttempt } = useSocket();
  const status = getStatusConfig(connectionState, reconnectAttempt);

  return (
    <div
      className="flex items-center gap-2"
      role="status"
      aria-live="polite"
      aria-atomic="true"
      aria-label={getAriaLabel(connectionState, reconnectAttempt)}
    >
      <span className="relative flex h-2 w-2" aria-hidden="true">
        {status.animate && (
          <span
            className={`absolute inset-0 rounded-full ${status.dotColor} opacity-40 animate-ping`}
          />
        )}
        <span
          className={`relative inline-flex h-2 w-2 rounded-full ${status.dotColor} ${status.glowColor}`}
        />
      </span>
      <span className={`text-xs font-mono ${status.textColor}`}>
        {status.text}
      </span>
    </div>
  );
}

export default ConnectionStatus;
