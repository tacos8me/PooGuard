import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { format } from 'date-fns';
import clsx from 'clsx';
import api from '../lib/api';
import { useAuth } from '../context/AuthContext';

const ACTION_TYPES = [
  { value: '', label: 'All Actions' },
  { value: 'config.update', label: 'Config Update' },
  { value: 'config.view', label: 'Config View' },
  { value: 'user.create', label: 'User Create' },
  { value: 'user.update', label: 'User Update' },
  { value: 'user.delete', label: 'User Delete' },
  { value: 'user.role_change', label: 'Role Change' },
  { value: 'alert.create', label: 'Alert Create' },
  { value: 'alert.update', label: 'Alert Update' },
  { value: 'alert.delete', label: 'Alert Delete' },
  { value: 'alert.acknowledge', label: 'Alert Acknowledge' },
  { value: 'session.reset', label: 'Session Reset' },
  { value: 'session.clear', label: 'Session Clear' },
  { value: 'auth.login_failure', label: 'Login Failure' },
  { value: 'auth.token_invalid', label: 'Invalid Token' },
  { value: 'auth.rate_limited', label: 'Rate Limited' },
  { value: 'auth.unauthorized', label: 'Unauthorized' },
];

const ACTION_COLORS = {
  'config.update': 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  'config.view': 'bg-zinc-500/15 text-zinc-400 border-zinc-500/30',
  'user.create': 'bg-primary-500/15 text-primary-400 border-primary-500/30',
  'user.update': 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
  'user.delete': 'bg-red-500/15 text-red-400 border-red-500/30',
  'user.role_change': 'bg-purple-500/15 text-purple-400 border-purple-500/30',
  'alert.create': 'bg-primary-500/15 text-primary-400 border-primary-500/30',
  'alert.update': 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
  'alert.delete': 'bg-red-500/15 text-red-400 border-red-500/30',
  'alert.acknowledge': 'bg-zinc-500/15 text-zinc-400 border-zinc-500/30',
  'session.reset': 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  'session.clear': 'bg-red-500/15 text-red-400 border-red-500/30',
  'auth.login_failure': 'bg-red-500/15 text-red-400 border-red-500/30',
  'auth.token_invalid': 'bg-red-500/15 text-red-400 border-red-500/30',
  'auth.rate_limited': 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  'auth.unauthorized': 'bg-red-500/15 text-red-400 border-red-500/30',
};

function ActionBadge({ action }) {
  const colors = ACTION_COLORS[action] || 'bg-zinc-500/15 text-zinc-400 border-zinc-500/30';
  return (
    <span className={`inline-flex items-center px-2 py-0.5 text-[10px] font-mono font-medium border ${colors}`}>
      {action}
    </span>
  );
}

function ValueDiff({ label, value }) {
  if (!value) return null;
  return (
    <div>
      <p className="text-[10px] font-mono uppercase tracking-wider text-dark-500 mb-1">{label}</p>
      <pre className="text-xs text-dark-300 font-mono bg-dark-950 border border-dark-800 rounded p-3 overflow-x-auto whitespace-pre-wrap leading-relaxed max-h-48 overflow-y-auto">
        {typeof value === 'string' ? value : JSON.stringify(value, null, 2)}
      </pre>
    </div>
  );
}

function AuditLog() {
  const { user } = useAuth();
  const [page, setPage] = useState(1);
  const [actionFilter, setActionFilter] = useState('');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [expandedId, setExpandedId] = useState(null);
  const limit = 50;

  const { data, isLoading, error } = useQuery({
    queryKey: ['audit-logs', page, actionFilter, startDate, endDate],
    queryFn: async () => {
      const params = new URLSearchParams({
        limit: limit.toString(),
        offset: ((page - 1) * limit).toString(),
      });
      if (actionFilter) params.append('action', actionFilter);
      if (startDate) params.append('startDate', new Date(startDate).toISOString());
      if (endDate) params.append('endDate', new Date(endDate).toISOString());
      const response = await api.get(`/api/analytics/audit?${params}`);
      return response.data;
    },
  });

  if (user?.role !== 'admin') {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-bold text-dark-100 tracking-tight">Audit Log</h1>
        <div className="bg-dark-900 border border-dark-700 rounded p-8 text-center">
          <svg className="mx-auto h-12 w-12 text-red-500/60 mb-4" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z" />
          </svg>
          <p className="text-dark-300 text-lg font-medium font-mono">Admin Access Required</p>
          <p className="text-dark-500 text-sm mt-2">Only administrators can view audit logs.</p>
        </div>
      </div>
    );
  }

  const logs = data?.logs || [];
  const total = data?.total || 0;
  const totalPages = Math.ceil(total / limit) || 1;

  const formatTimestamp = (ts) => {
    if (!ts) return '';
    const date = new Date(ts);
    if (isNaN(date.getTime())) return ts;
    return format(date, 'MMM dd, HH:mm:ss');
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-dark-100 tracking-tight">Audit Log</h1>
        <p className="text-dark-500 text-sm mt-1">Immutable record of all admin actions</p>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-3">
        <select
          value={actionFilter}
          onChange={(e) => { setActionFilter(e.target.value); setPage(1); }}
          className="px-4 py-2.5 bg-dark-950 border border-dark-700 rounded text-dark-100 font-mono text-sm focus:outline-none focus:ring-1 focus:ring-primary-500 focus:border-primary-500 transition-all duration-200 cursor-pointer"
        >
          {ACTION_TYPES.map((t) => (
            <option key={t.value} value={t.value}>{t.label}</option>
          ))}
        </select>
        <input
          type="date"
          value={startDate}
          onChange={(e) => { setStartDate(e.target.value); setPage(1); }}
          className="px-4 py-2.5 bg-dark-950 border border-dark-700 rounded text-dark-100 font-mono text-sm focus:outline-none focus:ring-1 focus:ring-primary-500 focus:border-primary-500 transition-all duration-200"
          placeholder="Start date"
        />
        <input
          type="date"
          value={endDate}
          onChange={(e) => { setEndDate(e.target.value); setPage(1); }}
          className="px-4 py-2.5 bg-dark-950 border border-dark-700 rounded text-dark-100 font-mono text-sm focus:outline-none focus:ring-1 focus:ring-primary-500 focus:border-primary-500 transition-all duration-200"
          placeholder="End date"
        />
        {(actionFilter || startDate || endDate) && (
          <button
            onClick={() => { setActionFilter(''); setStartDate(''); setEndDate(''); setPage(1); }}
            className="px-4 py-2.5 rounded bg-dark-800 border border-dark-600 text-dark-300 hover:text-dark-100 hover:border-dark-500 font-mono text-xs uppercase tracking-wider transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-primary-500"
          >
            Clear
          </button>
        )}
      </div>

      {/* Table */}
      <div className="bg-dark-900 border border-dark-800">
        {isLoading ? (
          <div className="p-12 flex items-center justify-center">
            <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-primary-500" />
          </div>
        ) : error ? (
          <div className="p-8 text-center text-red-400 font-mono text-sm">
            Failed to load audit logs: {error.message}
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="bg-dark-800">
                    <th scope="col" className="text-left py-3 px-5 text-[10px] font-mono font-semibold text-dark-500 uppercase tracking-widest">Time</th>
                    <th scope="col" className="text-left py-3 px-5 text-[10px] font-mono font-semibold text-dark-500 uppercase tracking-widest">User</th>
                    <th scope="col" className="text-left py-3 px-5 text-[10px] font-mono font-semibold text-dark-500 uppercase tracking-widest">Action</th>
                    <th scope="col" className="text-left py-3 px-5 text-[10px] font-mono font-semibold text-dark-500 uppercase tracking-widest">Resource</th>
                    <th scope="col" className="text-left py-3 px-5 text-[10px] font-mono font-semibold text-dark-500 uppercase tracking-widest">IP</th>
                    <th scope="col" className="text-left py-3 px-5 text-[10px] font-mono font-semibold text-dark-500 uppercase tracking-widest w-10"></th>
                  </tr>
                </thead>
                <tbody>
                  {logs.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="py-12 text-center text-dark-500 font-mono text-sm">
                        No audit logs found for the selected filters.
                      </td>
                    </tr>
                  ) : (
                    logs.map((log, index) => {
                      const isExpanded = expandedId === log.id;
                      const hasDetails = log.old_value || log.new_value || log.metadata;
                      return (
                        <tr
                          key={log.id}
                          className={clsx(
                            'border-b border-dark-800/50 transition-colors',
                            hasDetails && 'cursor-pointer hover:bg-dark-800/40',
                            index % 2 === 0 ? 'bg-dark-900' : 'bg-dark-950',
                            isExpanded && 'bg-dark-800/30'
                          )}
                          onClick={() => hasDetails && setExpandedId(isExpanded ? null : log.id)}
                        >
                          <td className="py-3 px-5" colSpan={isExpanded ? 6 : undefined}>
                            {isExpanded ? (
                              <div className="space-y-4">
                                <div className="flex items-center gap-4 flex-wrap">
                                  <span className="text-dark-400 text-xs font-mono whitespace-nowrap">
                                    {formatTimestamp(log.created_at)}
                                  </span>
                                  <span className="text-dark-300 text-xs font-mono">{log.user_email || `User #${log.user_id}`}</span>
                                  <ActionBadge action={log.action} />
                                  {log.resource && (
                                    <span className="text-dark-400 text-xs font-mono">
                                      {log.resource}{log.resource_id ? ` #${log.resource_id}` : ''}
                                    </span>
                                  )}
                                  <span className="text-dark-500 text-xs font-mono">{log.ip_address}</span>
                                </div>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                  <ValueDiff label="Before" value={log.old_value} />
                                  <ValueDiff label="After" value={log.new_value} />
                                </div>
                                {log.metadata && (
                                  <ValueDiff label="Metadata" value={log.metadata} />
                                )}
                              </div>
                            ) : (
                              <span className="text-dark-400 text-xs font-mono whitespace-nowrap">
                                {formatTimestamp(log.created_at)}
                              </span>
                            )}
                          </td>
                          {!isExpanded && (
                            <>
                              <td className="py-3 px-5">
                                <span className="text-dark-300 text-xs font-mono truncate max-w-[180px] block">
                                  {log.user_email || `User #${log.user_id}`}
                                </span>
                              </td>
                              <td className="py-3 px-5">
                                <ActionBadge action={log.action} />
                              </td>
                              <td className="py-3 px-5">
                                <span className="text-dark-400 text-xs font-mono">
                                  {log.resource}{log.resource_id ? ` #${log.resource_id}` : ''}
                                </span>
                              </td>
                              <td className="py-3 px-5">
                                <span className="text-dark-500 text-xs font-mono">{log.ip_address}</span>
                              </td>
                              <td className="py-3 px-5">
                                {hasDetails && (
                                  <svg className="w-3.5 h-3.5 text-dark-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                                  </svg>
                                )}
                              </td>
                            </>
                          )}
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            <div className="p-5 border-t border-dark-800 flex items-center justify-between">
              <p className="text-xs text-dark-500 font-mono">
                Page {page} of {totalPages} &middot; {total} total
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
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  disabled={page >= totalPages}
                  className="px-3 py-1.5 text-xs font-mono font-medium bg-dark-800 text-dark-400 hover:text-dark-200 border border-dark-700 disabled:opacity-30 disabled:cursor-not-allowed transition-all duration-150"
                  aria-label="Next page"
                >
                  NEXT
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

export default AuditLog;
