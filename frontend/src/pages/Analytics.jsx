import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  LineChart,
  Line,
  PieChart,
  Pie,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  Cell,
} from 'recharts';
import { format } from 'date-fns';
import clsx from 'clsx';
import api from '../lib/api';

const PERIODS = [
  { label: '24h', value: '24h' },
  { label: '7d', value: '7d' },
  { label: '30d', value: '30d' },
];

const FILTERS = [
  { label: 'All', value: 'all' },
  { label: 'Blocked', value: 'blocked' },
  { label: 'Flagged', value: 'flagged' },
  { label: 'Allowed', value: 'allowed' },
];

const THREAT_COLORS = {
  'Prompt Injection': '#ef4444',
  'Jailbreak': '#f97316',
  'PII': '#eab308',
};

const PIE_COLORS = ['#ef4444', '#f97316', '#eab308'];

const CHART_AXIS_STYLE = { fill: '#847668', fontSize: 11, fontFamily: 'JetBrains Mono, Fira Code, monospace' };
const CHART_GRID_COLOR = '#352e29';

// Shared tooltip wrapper style
function TooltipShell({ children }) {
  return (
    <div className="bg-dark-800 border border-dark-700 p-3 shadow-lg font-mono text-xs"
      style={{ borderRadius: 0 }}
    >
      {children}
    </div>
  );
}

// Custom tooltip for line chart
function LineChartTooltip({ active, payload, label, formatTimeLabel }) {
  if (!active || !payload?.length) return null;

  return (
    <TooltipShell>
      <p className="text-dark-400 mb-1.5">{formatTimeLabel(label)}</p>
      {payload.map((entry, index) => (
        <p key={index} style={{ color: entry.color }}>
          {entry.name}: {entry.value}
        </p>
      ))}
    </TooltipShell>
  );
}

// Custom tooltip for pie chart
function PieChartTooltip({ active, payload, totalThreats }) {
  if (!active || !payload?.length) return null;

  const percentage = payload[0].payload.percentage ||
    ((payload[0].value / (totalThreats || 1)) * 100).toFixed(1);

  return (
    <TooltipShell>
      <p className="text-dark-100 font-medium">{payload[0].name}</p>
      <p className="text-dark-400">{payload[0].value} threats ({percentage}%)</p>
    </TooltipShell>
  );
}

// Custom tooltip for bar chart
function BarChartTooltip({ active, payload, label, formatLabel }) {
  if (!active || !payload?.length) return null;

  return (
    <TooltipShell>
      <p className="text-dark-400 mb-1.5">{formatLabel(label)}</p>
      {payload.map((entry, index) => (
        <p key={index} style={{ color: entry.color || entry.fill }}>
          {entry.name}: {entry.value}
        </p>
      ))}
    </TooltipShell>
  );
}

// Summary stat card for the top metrics row
function StatCard({ label, value, color }) {
  return (
    <div className="bg-dark-900 border border-dark-700 p-4">
      <p className="text-dark-500 text-xs font-mono uppercase tracking-wider mb-1">{label}</p>
      <p className={clsx('text-2xl font-bold font-mono', color || 'text-dark-100')}>{value}</p>
    </div>
  );
}

// Loading spinner consistent with the dark theme
function ChartLoader() {
  return (
    <div className="h-80 flex items-center justify-center">
      <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-primary-500" />
    </div>
  );
}

function Analytics() {
  const [period, setPeriod] = useState('24h');
  const [filter, setFilter] = useState('all');
  const [page, setPage] = useState(1);

  // Fetch timeline data
  const { data: timelineData, isLoading: timelineLoading } = useQuery({
    queryKey: ['analytics', 'timeline', period],
    queryFn: async () => {
      const response = await api.get(`/api/analytics/timeline?period=${period}`);
      return response.data;
    },
  });

  // Fetch threat breakdown data
  const { data: threatsData, isLoading: threatsLoading } = useQuery({
    queryKey: ['analytics', 'threats'],
    queryFn: async () => {
      const response = await api.get('/api/analytics/threats');
      return response.data;
    },
  });

  // Fetch logs data
  const { data: logsData, isLoading: logsLoading } = useQuery({
    queryKey: ['analytics', 'logs', page, filter],
    queryFn: async () => {
      const params = new URLSearchParams({ page: page.toString() });
      if (filter !== 'all') params.append('action', filter);
      const response = await api.get(`/api/analytics/logs?${params}`);
      return response.data;
    },
  });

  // Format time label based on period
  const formatTimeLabel = (timestamp) => {
    if (!timestamp) return '';
    // Handle different timestamp formats
    const date = typeof timestamp === 'string' && timestamp.includes(' ')
      ? new Date(timestamp.replace(' ', 'T'))
      : new Date(timestamp);
    if (isNaN(date.getTime())) return timestamp;
    if (period === '24h') {
      return format(date, 'HH:mm');
    }
    return format(date, 'MMM dd');
  };

  // Get action badge styling
  const getActionBadge = (action) => {
    const styles = {
      blocked: 'bg-red-500/20 text-red-400 border-red-500/30',
      flagged: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
      allowed: 'bg-primary-500/20 text-primary-400 border-primary-500/30',
    };
    return styles[action] || styles.allowed;
  };

  // Get threat score color
  const getScoreColor = (score) => {
    if (score >= 0.7) return 'text-red-400';
    if (score >= 0.4) return 'text-amber-400';
    return 'text-primary-400';
  };

  // Format timestamp for logs
  const formatTimestamp = (timestamp) => {
    if (!timestamp) return '';
    const date = new Date(timestamp);
    if (isNaN(date.getTime())) return timestamp;
    return format(date, 'MMM dd, HH:mm:ss');
  };

  // Get threat data for pie chart (handle both API response formats)
  const getThreatData = () => {
    if (threatsData?.threats) return threatsData.threats;
    if (threatsData?.breakdown) return threatsData.breakdown;
    return [];
  };

  // Get timeline data (handle both API response formats)
  const getTimelineData = () => {
    return timelineData?.timeline || [];
  };

  // Get hourly distribution data
  const getHourlyData = () => {
    if (timelineData?.hourlyDistribution) return timelineData.hourlyDistribution;
    const timeline = getTimelineData();
    if (period === '24h' && timeline.length > 0) {
      return timeline.slice(-24);
    }
    return timeline.slice(-24);
  };

  // Derive block rate color from percentage value
  const getBlockRateColor = (rate) => {
    if (rate >= 50) return 'text-red-400';
    if (rate >= 25) return 'text-amber-400';
    return 'text-primary-400';
  };

  // Compute summary stats from timeline data
  const timelineRows = getTimelineData();
  const totalRequests = timelineRows.reduce((sum, row) => sum + (row.total || 0), 0);
  const totalBlocked = timelineRows.reduce((sum, row) => sum + (row.blocked || 0), 0);
  const totalFlagged = timelineRows.reduce((sum, row) => sum + (row.flagged || 0), 0);
  const blockRate = totalRequests > 0 ? ((totalBlocked / totalRequests) * 100) : 0;

  const formatHourLabel = (hour) => {
    if (typeof hour === 'number') return `${hour}:00`;
    return formatTimeLabel(hour);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-dark-100 tracking-tight">Analytics</h1>
          <p className="text-dark-500 text-sm font-mono mt-1">Threat patterns and request statistics</p>
        </div>

        {/* Period selector - pill tabs */}
        <div className="flex gap-1 bg-dark-900 border border-dark-700 p-1 rounded-full">
          {PERIODS.map((p) => (
            <button
              key={p.value}
              onClick={() => {
                setPeriod(p.value);
                setPage(1);
              }}
              className={clsx(
                'px-4 py-1.5 rounded-full text-sm font-mono font-medium transition-all duration-150',
                period === p.value
                  ? 'bg-primary-600/20 text-primary-400 border border-primary-500/30'
                  : 'text-dark-400 hover:text-dark-200 border border-transparent'
              )}
            >
              {p.label}
            </button>
          ))}
        </div>
      </div>

      {/* Summary Stats Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard label="Total Requests" value={totalRequests.toLocaleString()} color="text-primary-400" />
        <StatCard label="Blocked" value={totalBlocked.toLocaleString()} color="text-red-400" />
        <StatCard label="Flagged" value={totalFlagged.toLocaleString()} color="text-amber-400" />
        <StatCard
          label="Block Rate"
          value={`${blockRate.toFixed(1)}%`}
          color={getBlockRateColor(blockRate)}
        />
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Line Chart - Requests Over Time */}
        <div className="bg-dark-900 border border-dark-800 p-6 lg:col-span-2">
          <h2 className="text-sm font-mono font-semibold text-dark-300 uppercase tracking-wider mb-4">
            Requests Over Time
          </h2>
          {timelineLoading ? (
            <ChartLoader />
          ) : getTimelineData().length === 0 ? (
            <div className="h-80 flex items-center justify-center text-dark-500 font-mono text-sm">
              No request data for this period
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={320}>
              <LineChart data={getTimelineData()}>
                <CartesianGrid stroke={CHART_GRID_COLOR} strokeDasharray="3 3" />
                <XAxis
                  dataKey="time_bucket"
                  tickFormatter={formatTimeLabel}
                  stroke={CHART_GRID_COLOR}
                  tick={CHART_AXIS_STYLE}
                />
                <YAxis
                  stroke={CHART_GRID_COLOR}
                  tick={CHART_AXIS_STYLE}
                />
                <Tooltip content={<LineChartTooltip formatTimeLabel={formatTimeLabel} />} />
                <Legend
                  wrapperStyle={{ paddingTop: '16px', fontFamily: 'JetBrains Mono, Fira Code, monospace', fontSize: 11 }}
                  formatter={(value) => <span className="text-dark-400">{value}</span>}
                />
                <Line
                  type="linear"
                  dataKey="total"
                  name="Total"
                  stroke="#b07d4f"
                  strokeWidth={2}
                  dot={false}
                  activeDot={{ r: 4, fill: '#b07d4f', stroke: '#b07d4f', strokeWidth: 2 }}
                />
                <Line
                  type="linear"
                  dataKey="blocked"
                  name="Blocked"
                  stroke="#ef4444"
                  strokeWidth={2}
                  dot={false}
                  activeDot={{ r: 4, fill: '#ef4444', stroke: '#ef4444', strokeWidth: 2 }}
                />
              </LineChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Pie Chart - Threat Type Breakdown */}
        <div className="bg-dark-900 border border-dark-800 p-6">
          <h2 className="text-sm font-mono font-semibold text-dark-300 uppercase tracking-wider mb-4">
            Threat Breakdown
          </h2>
          {threatsLoading ? (
            <ChartLoader />
          ) : getThreatData().length === 0 ? (
            <div className="h-80 flex items-center justify-center text-dark-500 font-mono text-sm">
              No threats detected in this period
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={320}>
              <PieChart>
                <Pie
                  data={getThreatData()}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={100}
                  paddingAngle={5}
                  dataKey="count"
                  nameKey="type"
                  label={({ type, percent }) => `${type} (${(percent * 100).toFixed(0)}%)`}
                  labelLine={{ stroke: '#52525b' }}
                >
                  {getThreatData().map((entry, index) => (
                    <Cell
                      key={`cell-${index}`}
                      fill={THREAT_COLORS[entry.type] || PIE_COLORS[index % PIE_COLORS.length]}
                    />
                  ))}
                </Pie>
                <Tooltip content={<PieChartTooltip totalThreats={threatsData?.total} />} />
              </PieChart>
            </ResponsiveContainer>
          )}
          {/* Legend */}
          <div className="flex flex-wrap justify-center gap-4 mt-4">
            {getThreatData().map((threat, index) => (
              <div key={threat.type} className="flex items-center gap-2">
                <div
                  className="w-2.5 h-2.5"
                  style={{ backgroundColor: THREAT_COLORS[threat.type] || PIE_COLORS[index % PIE_COLORS.length] }}
                />
                <span className="text-dark-400 text-xs font-mono">{threat.type}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Bar Chart - Hourly Distribution */}
        <div className="bg-dark-900 border border-dark-800 p-6">
          <h2 className="text-sm font-mono font-semibold text-dark-300 uppercase tracking-wider mb-4">
            Hourly Distribution
          </h2>
          {timelineLoading ? (
            <ChartLoader />
          ) : getHourlyData().length === 0 ? (
            <div className="h-80 flex items-center justify-center text-dark-500 font-mono text-sm">
              No hourly data available
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={320}>
              <BarChart data={getHourlyData()}>
                <CartesianGrid stroke={CHART_GRID_COLOR} strokeDasharray="3 3" />
                <XAxis
                  dataKey="time_bucket"
                  stroke={CHART_GRID_COLOR}
                  tick={CHART_AXIS_STYLE}
                  tickFormatter={formatHourLabel}
                  label={{ value: 'Hour', position: 'insideBottomRight', offset: -5, style: { fill: '#6b6b6b', fontFamily: 'JetBrains Mono, Fira Code, monospace', fontSize: 10 } }}
                />
                <YAxis
                  stroke={CHART_GRID_COLOR}
                  tick={CHART_AXIS_STYLE}
                  label={{ value: 'Requests', angle: -90, position: 'insideLeft', offset: 10, style: { fill: '#6b6b6b', fontFamily: 'JetBrains Mono, Fira Code, monospace', fontSize: 10 } }}
                />
                <Tooltip content={<BarChartTooltip formatLabel={formatHourLabel} />} />
                <Bar dataKey="total" name="Total" fill="#b07d4f" radius={[2, 2, 0, 0]} />
                <Bar dataKey="blocked" name="Blocked" fill="#ef4444" radius={[2, 2, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Data Table */}
      <div className="bg-dark-900 border border-dark-800">
        <div className="p-5 border-b border-dark-800">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <h2 className="text-sm font-mono font-semibold text-dark-300 uppercase tracking-wider">
              Recent Logs
            </h2>
            <div className="flex gap-1">
              {FILTERS.map((f) => (
                <button
                  key={f.value}
                  onClick={() => {
                    setFilter(f.value);
                    setPage(1);
                  }}
                  className={clsx(
                    'px-3 py-1 rounded-full text-xs font-mono font-medium transition-all duration-150',
                    filter === f.value
                      ? 'bg-primary-600/20 text-primary-400 border border-primary-500/30'
                      : 'text-dark-400 hover:text-dark-200 border border-transparent'
                  )}
                >
                  {f.label}
                </button>
              ))}
            </div>
          </div>
        </div>

        {logsLoading ? (
          <div className="p-12 flex items-center justify-center">
            <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-primary-500" />
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="bg-dark-800">
                    <th scope="col" className="text-left py-3 px-5 text-[10px] font-mono font-semibold text-dark-500 uppercase tracking-widest">Time</th>
                    <th scope="col" className="text-left py-3 px-5 text-[10px] font-mono font-semibold text-dark-500 uppercase tracking-widest">Input Preview</th>
                    <th scope="col" className="text-left py-3 px-5 text-[10px] font-mono font-semibold text-dark-500 uppercase tracking-widest">Threat Scores</th>
                    <th scope="col" className="text-left py-3 px-5 text-[10px] font-mono font-semibold text-dark-500 uppercase tracking-widest">Action</th>
                    <th scope="col" className="text-left py-3 px-5 text-[10px] font-mono font-semibold text-dark-500 uppercase tracking-widest">Latency</th>
                  </tr>
                </thead>
                <tbody>
                  {(logsData?.logs || []).length === 0 ? (
                    <tr>
                      <td colSpan={5} className="py-12 text-center text-dark-500 font-mono text-sm">
                        No logs found for the selected filter.
                      </td>
                    </tr>
                  ) : (
                    (logsData?.logs || []).map((log, index) => (
                      <tr
                        key={log.id}
                        className={clsx(
                          'border-b border-dark-800/50 hover:bg-dark-800/40 transition-colors',
                          index % 2 === 0 ? 'bg-dark-900' : 'bg-dark-950'
                        )}
                      >
                        <td className="py-3 px-5">
                          <span className="text-dark-400 text-xs font-mono whitespace-nowrap">
                            {formatTimestamp(log.timestamp)}
                          </span>
                        </td>
                        <td className="py-3 px-5">
                          <p className="text-dark-200 text-xs font-mono truncate max-w-xs" title={log.input_text || log.input}>
                            {(log.input_text || log.input || '').substring(0, 50)}
                            {(log.input_text || log.input || '').length > 50 ? '...' : ''}
                          </p>
                        </td>
                        <td className="py-3 px-5">
                          <div className="flex items-center gap-3">
                            {(log.threat_scores || log.scores) && (
                              <>
                                <span className={clsx('text-[10px] font-mono whitespace-nowrap', getScoreColor(log.threat_scores?.prompt_injection || log.scores?.injection || 0))}>
                                  INJ {((log.threat_scores?.prompt_injection || log.scores?.injection || 0) * 100).toFixed(0)}%
                                </span>
                                <span className={clsx('text-[10px] font-mono whitespace-nowrap', getScoreColor(log.threat_scores?.jailbreak || log.scores?.jailbreak || 0))}>
                                  JB {((log.threat_scores?.jailbreak || log.scores?.jailbreak || 0) * 100).toFixed(0)}%
                                </span>
                                <span className={clsx('text-[10px] font-mono whitespace-nowrap', getScoreColor(log.threat_scores?.pii || log.scores?.pii || 0))}>
                                  PII {((log.threat_scores?.pii || log.scores?.pii || 0) * 100).toFixed(0)}%
                                </span>
                              </>
                            )}
                          </div>
                        </td>
                        <td className="py-3 px-5">
                          <span
                            className={clsx(
                              'inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-medium border',
                              getActionBadge(log.action)
                            )}
                          >
                            {log.action ? log.action.toUpperCase() : 'UNKNOWN'}
                          </span>
                        </td>
                        <td className="py-3 px-5">
                          <span className="text-dark-400 text-xs font-mono">{log.latency_ms || log.latency || 0}ms</span>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {logsData?.pagination && (
              <div className="p-5 border-t border-dark-800 flex items-center justify-between">
                <p className="text-xs text-dark-500 font-mono">
                  Page {logsData.pagination.page} of {logsData.pagination.pages || logsData.pagination.totalPages || 1}
                  {' '}&middot;{' '}
                  {logsData.pagination.total || 0} total
                </p>
                <div className="flex gap-2" role="navigation" aria-label="Pagination">
                  <button
                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                    disabled={page === 1}
                    className="px-3 py-1.5 text-xs font-mono font-medium bg-dark-800 text-dark-400 hover:text-dark-200 border border-dark-700 disabled:opacity-30 disabled:cursor-not-allowed transition-all duration-150"
                    aria-label="Previous page"
                  >
                    PREV
                  </button>
                  <button
                    onClick={() => setPage((p) => Math.min(logsData.pagination.pages || logsData.pagination.totalPages || 1, p + 1))}
                    disabled={page >= (logsData.pagination.pages || logsData.pagination.totalPages || 1)}
                    className="px-3 py-1.5 text-xs font-mono font-medium bg-dark-800 text-dark-400 hover:text-dark-200 border border-dark-700 disabled:opacity-30 disabled:cursor-not-allowed transition-all duration-150"
                    aria-label="Next page"
                  >
                    NEXT
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

export default Analytics;
