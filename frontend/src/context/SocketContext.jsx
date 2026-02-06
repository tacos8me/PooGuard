import { createContext, useContext, useState, useEffect, useRef, useCallback } from 'react';
import { io } from 'socket.io-client';
import { useAuth } from './AuthContext';

const SocketContext = createContext(null);

// Connection states
export const CONNECTION_STATES = {
  CONNECTED: 'connected',
  DISCONNECTED: 'disconnected',
  RECONNECTING: 'reconnecting',
};

export function SocketProvider({ children }) {
  const { token } = useAuth();
  const [connectionState, setConnectionState] = useState(CONNECTION_STATES.DISCONNECTED);
  const [reconnectAttempt, setReconnectAttempt] = useState(0);
  const [socket, setSocket] = useState(null);
  const socketRef = useRef(null);
  const tokenRef = useRef(token);

  // Keep tokenRef in sync so reconnection handlers always have the latest token
  useEffect(() => {
    tokenRef.current = token;

    // Update the auth on the live socket so the next reconnection attempt
    // uses the fresh token instead of the one captured at creation time.
    if (socketRef.current) {
      socketRef.current.auth = { token };
    }
  }, [token]);

  // Connect to socket when token is available
  useEffect(() => {
    if (!token) {
      setConnectionState(CONNECTION_STATES.DISCONNECTED);
      return;
    }

    // Create socket connection
    const newSocket = io({
      auth: {
        token: token,
      },
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionAttempts: 25,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
    });

    socketRef.current = newSocket;
    setSocket(newSocket);

    // Check initial connection state
    if (newSocket.connected) {
      setConnectionState(CONNECTION_STATES.CONNECTED);
    }

    // Connection established
    newSocket.on('connect', () => {
      setConnectionState(CONNECTION_STATES.CONNECTED);
      setReconnectAttempt(0);
    });

    // Connection lost
    newSocket.on('disconnect', (reason) => {
      if (reason === 'io server disconnect') {
        // Server disconnected, won't reconnect automatically
        setConnectionState(CONNECTION_STATES.DISCONNECTED);
      } else {
        // Client disconnected, will attempt to reconnect
        setConnectionState(CONNECTION_STATES.RECONNECTING);
      }
    });

    // Reconnection attempt — update auth with latest token before each retry
    newSocket.on('reconnect_attempt', (attempt) => {
      newSocket.auth = { token: tokenRef.current };
      setConnectionState(CONNECTION_STATES.RECONNECTING);
      setReconnectAttempt(attempt);
    });

    // Reconnection successful
    newSocket.on('reconnect', () => {
      setConnectionState(CONNECTION_STATES.CONNECTED);
      setReconnectAttempt(0);
      window.dispatchEvent(new Event('socket:reconnected'));
    });

    // Reconnection failed after all attempts
    newSocket.on('reconnect_failed', () => {
      setConnectionState(CONNECTION_STATES.DISCONNECTED);
      setReconnectAttempt(0);
    });

    // Connection error
    newSocket.on('connect_error', (error) => {
      setConnectionState(CONNECTION_STATES.RECONNECTING);
      if (import.meta.env.DEV) {
        console.error('WebSocket connection error:', error);
      }
    });

    // Cleanup on unmount or token change
    return () => {
      newSocket.disconnect();
      socketRef.current = null;
      setSocket(null);
    };
  }, [token]);

  // Manual reconnect function
  const reconnect = useCallback(() => {
    if (!socketRef.current) {
      return;
    }
    setConnectionState(CONNECTION_STATES.RECONNECTING);
    socketRef.current.disconnect();
    socketRef.current.connect();
  }, []);

  const value = {
    socket,
    connectionState,
    isConnected: connectionState === CONNECTION_STATES.CONNECTED,
    isReconnecting: connectionState === CONNECTION_STATES.RECONNECTING,
    reconnectAttempt,
    reconnect,
  };

  return <SocketContext.Provider value={value}>{children}</SocketContext.Provider>;
}

export function useSocket() {
  const context = useContext(SocketContext);
  if (!context) {
    throw new Error('useSocket must be used within a SocketProvider');
  }
  return context;
}

export default SocketContext;
