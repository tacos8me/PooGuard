import { useState, useEffect, useRef, useMemo } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { format } from 'date-fns';
import clsx from 'clsx';
import api from '../lib/api';
import { useSocket } from '../context/SocketContext';

// Fetch analytics summary
const fetchAnalyticsSummary = async () => {
  const response = await api.get('/api/analytics/summary');
  return response.data;
};

// Stats Card Component
function StatsCard({ title, value, subtitle, accentColor, trend }) {
  const accentStyles = {
    cyan: 'border-l-cyan-500 shadow-glow-cyan-sm',
    red: 'border-l-red-500 shadow-glow-red-sm',
    amber: 'border-l-amber-500',
    green: 'border-l-primary-500 shadow-glow-green-sm',
  };

  const valueStyles = {
    cyan: 'text-cyan-400',
    red: 'text-red-400',
    amber: 'text-amber-400',
    green: 'text-primary-400',
  };

  return (
    <div
      className={clsx(
        'bg-zinc-900 border border-zinc-800 rounded-lg p-5 border-l-[3px]',
        accentStyles[accentColor]
      )}
    >
      <p className="text-zinc-500 text-xs font-medium uppercase tracking-wider">
        {title}
      </p>
      <p
        className={clsx(
          'text-3xl font-bold font-mono mt-2',
          valueStyles[accentColor] || 'text-zinc-100'
        )}
      >
        {value}
      </p>
      {subtitle && (
        <p className="text-zinc-500 text-xs mt-1.5 font-mono">{subtitle}</p>
      )}
      {trend !== undefined && (
        <div
          className={clsx(
            'mt-3 text-xs font-mono flex items-center gap-1.5',
            trend >= 0 ? 'text-red-400' : 'text-primary-400'
          )}
        >
          <span>
            {trend >= 0 ? '+' : ''}
            {trend}%
          </span>
          <span className="text-zinc-600">vs last hour</span>
        </div>
      )}
    </div>
  );
}

// Threat Level Gauge Component
function ThreatLevelGauge({ level }) {
  const levels = {
    low: {
      color: 'bg-primary-500',
      text: 'LOW',
      width: '25%',
      pct: 25,
      glow: 'shadow-glow-green-sm',
      badge: 'bg-primary-500/10 text-primary-400 border-primary-500/20',
    },
    medium: {
      color: 'bg-amber-500',
      text: 'MEDIUM',
      width: '50%',
      pct: 50,
      glow: '',
      badge: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
    },
    high: {
      color: 'bg-orange-500',
      text: 'HIGH',
      width: '75%',
      pct: 75,
      glow: '',
      badge: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
    },
    critical: {
      color: 'bg-red-500',
      text: 'CRITICAL',
      width: '100%',
      pct: 100,
      glow: 'shadow-glow-red-sm',
      badge: 'bg-red-500/10 text-red-400 border-red-500/20',
    },
  };

  const currentLevel = levels[level] || levels.low;

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-5">
      <div className="flex items-center justify-between mb-1">
        <h3 className="text-zinc-500 text-xs font-medium uppercase tracking-wider">
          Threat Level
        </h3>
        <span
          className={clsx(
            'px-2 py-0.5 rounded text-xs font-mono font-medium border',
            currentLevel.badge
          )}
        >
          {currentLevel.text}
        </span>
      </div>
      <p className="text-2xl font-bold font-mono text-zinc-100 mb-4">
        {currentLevel.pct}
        <span className="text-sm text-zinc-600 ml-0.5">%</span>
      </p>
      <div className="h-2 bg-zinc-800 rounded-full overflow-hidden">
        <div
          className={clsx(
            'h-full rounded-full transition-all duration-700',
            currentLevel.color,
            currentLevel.glow
          )}
          style={{ width: currentLevel.width }}
        />
      </div>
      <div className="flex justify-between mt-2 text-[10px] font-mono text-zinc-600">
        <span>LOW</span>
        <span>MED</span>
        <span>HIGH</span>
        <span>CRIT</span>
      </div>
    </div>
  );
}

// Action Badge Component
function ActionBadge({ action }) {
  const badgeStyles = {
    blocked: 'bg-red-500/10 text-red-400 border-red-500/20',
    flagged: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
    allowed: 'bg-primary-500/10 text-primary-400 border-primary-500/20',
  };

  return (
    <span
      className={clsx(
        'px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase tracking-wider border',
        badgeStyles[action] || badgeStyles.allowed
      )}
    >
      {action}
    </span>
  );
}

// Threat Score Preview Component
function ThreatScorePreview({ scores }) {
  if (!scores) return null;

  const scoreItems = [
    { key: 'prompt_injection', label: 'INJ' },
    { key: 'jailbreak', label: 'JB' },
    { key: 'semantic_similarity', label: 'SEM' },
    { key: 'pii', label: 'PII' },
  ];

  function getScoreColor(value) {
    if (value === undefined) return 'text-zinc-600';
    if (value > 0.7) return 'text-red-400';
    if (value > 0.4) return 'text-amber-400';
    return 'text-zinc-500';
  }

  return (
    <div className="flex gap-3 text-[10px] font-mono">
      {scoreItems.map(({ key, label }) => (
        <span key={key} className="flex items-center gap-1">
          <span className="text-zinc-600">{label}</span>
          <span className={getScoreColor(scores[key])}>
            {scores[key] !== undefined
              ? (scores[key] * 100).toFixed(0)
              : '--'}
          </span>
        </span>
      ))}
    </div>
  );
}

// Event Item Component
function EventItem({ event, isExpanded, onToggle }) {
  const timestamp = event.timestamp
    ? format(new Date(event.timestamp), 'HH:mm:ss')
    : '--:--:--';

  const rowBg = {
    blocked: 'bg-red-500/[0.04]',
    flagged: 'bg-amber-500/[0.04]',
  };

  // Handle keyboard navigation for expandable items
  function handleKeyDown(e) {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      onToggle();
    }
  }

  return (
    <div
      className={clsx(
        'px-4 py-3 border-b border-zinc-800/60 hover:bg-zinc-800/40 transition-colors cursor-pointer',
        'focus:outline-none focus:ring-1 focus:ring-primary-500/50 focus:ring-inset',
        rowBg[event.action],
        isExpanded && 'bg-zinc-800/30'
      )}
      onClick={onToggle}
      onKeyDown={handleKeyDown}
      tabIndex={0}
      role="button"
      aria-expanded={isExpanded}
      aria-label={`Security event at ${timestamp}, action: ${event.action || 'unknown'}. ${isExpanded ? 'Press Enter to collapse' : 'Press Enter to expand'}`}
    >
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-3 flex-1 min-w-0">
          <span className="text-zinc-600 text-xs font-mono whitespace-nowrap">
            {timestamp}
          </span>
          <ActionBadge action={event.action} />
          <ThreatScorePreview scores={event.threat_scores || event.threatScores} />
        </div>
        <span className="p-0.5" aria-hidden="true">
          <svg
            className={clsx(
              'w-3.5 h-3.5 text-zinc-600 transition-transform',
              isExpanded && 'rotate-180'
            )}
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M19 9l-7 7-7-7"
            />
          </svg>
        </span>
      </div>
      {isExpanded && event.input_text && (
        <div className="mt-2.5 p-3 bg-zinc-950 rounded border border-zinc-800">
          <p className="text-zinc-600 text-[10px] font-mono uppercase tracking-wider mb-1.5">
            Input Text
          </p>
          <p className="text-zinc-300 text-xs font-mono break-all leading-relaxed">
            {event.input_text.length > 200
              ? `${event.input_text.substring(0, 200)}...`
              : event.input_text}
          </p>
        </div>
      )}
    </div>
  );
}

// Live Request Feed Component
function LiveRequestFeed({ events, maxItems = 50 }) {
  const [expandedId, setExpandedId] = useState(null);
  const feedRef = useRef(null);
  const { connectionState, reconnectAttempt } = useSocket();
  const displayedEvents = useMemo(
    () => events.slice(0, maxItems),
    [events, maxItems]
  );

  function handleToggle(eventId) {
    setExpandedId(expandedId === eventId ? null : eventId);
  }

  const connectionConfig = (() => {
    switch (connectionState) {
      case 'connected':
        return { dotColor: 'bg-primary-500', pingColor: 'bg-primary-400', textColor: 'text-primary-500', text: 'Connected', animate: true };
      case 'reconnecting':
        return { dotColor: 'bg-amber-500', pingColor: 'bg-amber-400', textColor: 'text-amber-400', text: reconnectAttempt > 1 ? `Reconnecting (${reconnectAttempt})...` : 'Reconnecting...', animate: true };
      case 'disconnected':
      default:
        return { dotColor: 'bg-red-500', pingColor: 'bg-red-400', textColor: 'text-red-400', text: 'Disconnected', animate: false };
    }
  })();

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden flex flex-col h-[540px]">
      <div className="px-5 py-3.5 border-b border-zinc-800 flex items-center justify-between">
        <h3 className="text-zinc-500 text-xs font-medium uppercase tracking-wider">
          Live Feed
        </h3>
        <div className="flex items-center gap-2">
          <span className="relative flex h-2 w-2">
            {connectionConfig.animate && (
              <span className={`animate-ping absolute inline-flex h-full w-full rounded-full ${connectionConfig.pingColor} opacity-75`} />
            )}
            <span className={`relative inline-flex rounded-full h-2 w-2 ${connectionConfig.dotColor}`} />
          </span>
          <span className={`${connectionConfig.textColor} text-[10px] font-mono uppercase tracking-wider`}>
            {connectionConfig.text}
          </span>
        </div>
      </div>
      <div
        ref={feedRef}
        className="flex-1 overflow-y-auto relative"
        aria-live="polite"
        aria-label="Live security events feed"
      >
        {/* Top fade gradient */}
        <div className="sticky top-0 h-4 bg-gradient-to-b from-zinc-900 to-transparent z-10 pointer-events-none" />
        {displayedEvents.length === 0 ? (
          <div className="flex items-center justify-center h-full text-zinc-600 font-mono text-sm">
            <div className="text-center">
              <p className="mb-1">Waiting for events...</p>
              <p className="text-[10px] text-zinc-700">
                Events will appear here in real time
              </p>
            </div>
          </div>
        ) : (
          displayedEvents.map((event, index) => (
            <EventItem
              key={event.id || index}
              event={event}
              isExpanded={expandedId === (event.id || index)}
              onToggle={() => handleToggle(event.id || index)}
            />
          ))
        )}
        {/* Bottom fade gradient */}
        <div className="sticky bottom-0 h-4 bg-gradient-to-t from-zinc-900 to-transparent z-10 pointer-events-none" />
      </div>
    </div>
  );
}

// Quick Stats Sidebar Component
function QuickStats({ events }) {
  const blocked = events.filter((e) => e.action === 'blocked').length;
  const flagged = events.filter((e) => e.action === 'flagged').length;
  const allowed = events.filter((e) => e.action === 'allowed').length;
  const total = events.length;

  const items = [
    { label: 'Blocked', value: blocked, color: 'text-red-400', dot: 'bg-red-500' },
    { label: 'Flagged', value: flagged, color: 'text-amber-400', dot: 'bg-amber-500' },
    { label: 'Allowed', value: allowed, color: 'text-primary-400', dot: 'bg-primary-500' },
    { label: 'Total', value: total, color: 'text-cyan-400', dot: 'bg-cyan-500' },
  ];

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-5">
      <h3 className="text-zinc-500 text-xs font-medium uppercase tracking-wider mb-4">
        Event Breakdown
      </h3>
      <div className="space-y-3">
        {items.map(({ label, value, color, dot }) => (
          <div key={label} className="flex justify-between items-center">
            <div className="flex items-center gap-2">
              <span className={clsx('w-1.5 h-1.5 rounded-full', dot)} />
              <span className="text-zinc-400 text-sm">{label}</span>
            </div>
            <span className={clsx('font-mono font-semibold text-sm', color)}>
              {value}
            </span>
          </div>
        ))}
      </div>
      {total > 0 && (
        <div className="mt-4 pt-3 border-t border-zinc-800">
          <div className="flex h-1.5 rounded-full overflow-hidden bg-zinc-800">
            {blocked > 0 && (
              <div
                className="bg-red-500 transition-all duration-500"
                style={{ width: `${(blocked / total) * 100}%` }}
              />
            )}
            {flagged > 0 && (
              <div
                className="bg-amber-500 transition-all duration-500"
                style={{ width: `${(flagged / total) * 100}%` }}
              />
            )}
            {allowed > 0 && (
              <div
                className="bg-primary-500 transition-all duration-500"
                style={{ width: `${(allowed / total) * 100}%` }}
              />
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// Main Dashboard Component
export default function Dashboard() {
  const { socket } = useSocket();
  const queryClient = useQueryClient();
  const [events, setEvents] = useState([]);
  const [stats, setStats] = useState({
    requestsPerMinute: 0,
    blockRate: 0,
    activeThreats: 0,
    avgLatency: 0,
  });
  const [threatLevel, setThreatLevel] = useState('low');

  const pendingEventsRef = useRef([]);
  const flushTimeoutRef = useRef(null);

  const debouncedInvalidateAnalytics = useMemo(() => {
    let timer;
    return () => {
      clearTimeout(timer);
      timer = setTimeout(() => {
        queryClient.invalidateQueries({ queryKey: ['analytics-summary'] });
      }, 2000);
    };
  }, [queryClient]);

  // Fetch initial analytics data
  const {
    data: analyticsData,
    isLoading,
    error,
  } = useQuery({
    queryKey: ['analytics-summary'],
    queryFn: fetchAnalyticsSummary,
    refetchInterval: 60000,
    staleTime: 30000,
  });

  // Update stats when analytics data changes
  useEffect(() => {
    if (analyticsData) {
      setStats({
        requestsPerMinute: analyticsData.requests_per_minute || 0,
        blockRate: analyticsData.block_rate || 0,
        activeThreats: analyticsData.active_threats_today || 0,
        avgLatency: analyticsData.avg_latency_ms || 0,
      });
      setThreatLevel(analyticsData.threat_level || 'low');

      // Set initial events if available
      if (analyticsData.recent_events) {
        setEvents(analyticsData.recent_events);
      }
    }
  }, [analyticsData]);

  useEffect(() => {
    if (!socket) return;

    const handleFirewallEvent = (event) => {
      pendingEventsRef.current.push(event);

      if (!flushTimeoutRef.current) {
        flushTimeoutRef.current = setTimeout(() => {
          const pending = pendingEventsRef.current;
          pendingEventsRef.current = [];
          flushTimeoutRef.current = null;

          if (pending.length === 0) return;

          setEvents((prev) => {
            const merged = [...pending, ...prev];
            return merged.slice(0, 100);
          });

          setStats((prevStats) => {
            const newStats = { ...prevStats };
            for (const evt of pending) {
              if (evt.action === 'blocked' || evt.action === 'flagged') {
                newStats.activeThreats += 1;
              }
              if (evt.action === 'blocked') {
                newStats.blockRate = Math.min(
                  100,
                  newStats.blockRate + 0.1
                );
              }
            }
            return newStats;
          });

          const lastEvent = pending[pending.length - 1];
          const scores = lastEvent.threat_scores || lastEvent.threatScores;
          if (scores) {
            const maxScore = Math.max(
              scores.prompt_injection || 0,
              scores.jailbreak || 0,
              scores.semantic_similarity || 0,
              scores.pii || 0
            );

            if (maxScore > 0.9) {
              setThreatLevel('critical');
            } else if (maxScore > 0.7) {
              setThreatLevel('high');
            } else if (maxScore > 0.5) {
              setThreatLevel('medium');
            }
          }

          debouncedInvalidateAnalytics();
        }, 100);
      }
    };

    socket.on('firewall:event', handleFirewallEvent);

    return () => {
      socket.off('firewall:event', handleFirewallEvent);
      if (flushTimeoutRef.current) {
        clearTimeout(flushTimeoutRef.current);
        flushTimeoutRef.current = null;
      }
    };
  }, [socket, debouncedInvalidateAnalytics]);

  // Format display values
  function formatBlockRate(rate) {
    if (typeof rate === 'number') {
      return `${rate.toFixed(1)}%`;
    }
    return '0%';
  }

  function formatLatency(ms) {
    if (typeof ms === 'number') {
      return `${ms.toFixed(0)}ms`;
    }
    return '0ms';
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="flex flex-col items-center gap-3">
          <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-primary-500" />
          <span className="text-zinc-600 text-xs font-mono uppercase tracking-wider">
            Loading
          </span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-zinc-900 border border-red-500/20 rounded-lg p-6 text-center">
        <p className="text-red-400 font-mono text-sm">
          Failed to load dashboard data
        </p>
        <p className="text-zinc-600 text-xs font-mono mt-2">{error.message}</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex items-center justify-between border-b border-zinc-800 pb-4">
        <div>
          <h1 className="text-lg font-semibold text-zinc-100 tracking-tight">
            Real-Time Monitoring
          </h1>
          <p className="text-zinc-600 text-xs font-mono mt-0.5">
            Security operations overview
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary-400 opacity-75" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-primary-500" />
          </span>
          <span className="text-zinc-500 text-xs font-mono">ACTIVE</span>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatsCard
          title="Requests / Min"
          value={typeof stats.requestsPerMinute === 'number' ? stats.requestsPerMinute.toLocaleString() : '0'}
          subtitle="Last hour average"
          accentColor="cyan"
        />
        <StatsCard
          title="Block Rate"
          value={formatBlockRate(stats.blockRate)}
          subtitle="Threats blocked"
          accentColor="red"
        />
        <StatsCard
          title="Active Threats"
          value={typeof stats.activeThreats === 'number' ? stats.activeThreats.toLocaleString() : '0'}
          subtitle="Detected today"
          accentColor="amber"
        />
        <StatsCard
          title="Avg Latency"
          value={formatLatency(stats.avgLatency)}
          subtitle="Processing time"
          accentColor="green"
        />
      </div>

      {/* Threat Level, Quick Stats, and Live Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1 space-y-4">
          <ThreatLevelGauge level={threatLevel} />
          <QuickStats events={events} />
        </div>

        <div className="lg:col-span-2">
          <LiveRequestFeed events={events} />
        </div>
      </div>
    </div>
  );
}
