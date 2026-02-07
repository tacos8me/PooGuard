import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { format } from 'date-fns';
import clsx from 'clsx';
import api from '../lib/api';
import { useAuth } from '../context/AuthContext';
import ConfirmDialog from '../components/ConfirmDialog';

function ScoreBar({ score, threshold }) {
  const pct = Math.min(score / (threshold * 2), 1) * 100;
  const color = score >= threshold ? 'bg-red-500' : score >= threshold * 0.5 ? 'bg-amber-500' : 'bg-primary-500';
  return (
    <div className="relative w-full h-1.5 bg-dark-800 rounded-full overflow-hidden">
      <div
        className={`h-full rounded-full transition-all duration-500 ${color}`}
        style={{ width: `${pct}%` }}
      />
      <div
        className="absolute top-0 h-full w-px bg-dark-400/50"
        style={{ left: `${Math.min(threshold / (threshold * 2), 1) * 100}%` }}
        title={`Threshold: ${threshold}`}
      />
    </div>
  );
}

function SessionRow({ session, threshold, isExpanded, onToggle, onResetAlert, onDeleteSession, isResetting, isDeleting }) {
  const lastSeen = session.lastUpdateTime
    ? format(new Date(session.lastUpdateTime), 'MMM dd, HH:mm:ss')
    : '--';

  const scoreColor = session.cumulativeScore >= threshold
    ? 'text-red-400'
    : session.cumulativeScore >= threshold * 0.5
      ? 'text-amber-400'
      : 'text-primary-400';

  return (
    <div className={clsx(
      'border-b border-dark-800/50 transition-colors',
      isExpanded && 'bg-dark-800/20'
    )}>
      <div
        className="px-5 py-4 flex items-center justify-between gap-4 cursor-pointer hover:bg-dark-800/40 transition-colors"
        onClick={onToggle}
        onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onToggle(); } }}
        tabIndex={0}
        role="button"
        aria-expanded={isExpanded}
      >
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3 flex-wrap">
            <span className="text-dark-200 text-xs font-mono truncate max-w-[200px]" title={session.sessionId}>
              {session.sessionId}
            </span>
            {session.isAuthenticated ? (
              <span className="px-2 py-0.5 text-[10px] font-mono font-medium bg-primary-500/15 text-primary-400 border border-primary-500/30">
                AUTH
              </span>
            ) : (
              <span className="px-2 py-0.5 text-[10px] font-mono font-medium bg-zinc-500/15 text-zinc-400 border border-zinc-500/30">
                ANON
              </span>
            )}
            {session.alertTriggered && (
              <span className="px-2 py-0.5 text-[10px] font-mono font-medium bg-red-500/10 text-red-400 border border-red-500/20 animate-pulse">
                ALERT ({session.alertCount})
              </span>
            )}
          </div>
          <div className="flex items-center gap-4 mt-1.5">
            <span className="text-dark-500 text-[10px] font-mono">Last: {lastSeen}</span>
            <span className="text-dark-500 text-[10px] font-mono">{session.requestCount} reqs</span>
            <span className="text-dark-500 text-[10px] font-mono">{session.threatCount} threats</span>
          </div>
        </div>
        <div className="flex items-center gap-4 shrink-0">
          <div className="text-right">
            <span className={`text-sm font-mono font-bold tabular-nums ${scoreColor}`}>
              {session.cumulativeScore.toFixed(2)}
            </span>
            <p className="text-[10px] text-dark-500 font-mono">/ {threshold}</p>
          </div>
          <svg className={clsx('w-3.5 h-3.5 text-dark-600 transition-transform', isExpanded && 'rotate-180')} fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      </div>

      {isExpanded && (
        <SessionDetail
          sessionId={session.sessionId}
          threshold={threshold}
          onResetAlert={onResetAlert}
          onDeleteSession={onDeleteSession}
          isResetting={isResetting}
          isDeleting={isDeleting}
          alertTriggered={session.alertTriggered}
        />
      )}
    </div>
  );
}

function SessionDetail({ sessionId, threshold, onResetAlert, onDeleteSession, isResetting, isDeleting, alertTriggered }) {
  const { data: detail, isLoading } = useQuery({
    queryKey: ['session-detail', sessionId],
    queryFn: async () => {
      const response = await api.get(`/api/analytics/sessions/${encodeURIComponent(sessionId)}`);
      return response.data;
    },
  });

  if (isLoading) {
    return (
      <div className="px-5 pb-4">
        <div className="p-6 flex items-center justify-center">
          <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-primary-500" />
        </div>
      </div>
    );
  }

  if (!detail) {
    return (
      <div className="px-5 pb-4">
        <div className="p-4 text-center text-dark-500 font-mono text-sm">Failed to load session details.</div>
      </div>
    );
  }

  return (
    <div className="px-5 pb-4 space-y-4 animate-fade-in">
      {/* Score overview */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="bg-dark-950 border border-dark-800 rounded p-3">
          <p className="text-[10px] font-mono uppercase tracking-wider text-dark-500 mb-1">Cumulative Score</p>
          <p className="text-lg font-mono font-bold text-dark-100">{detail.cumulativeScore.toFixed(3)}</p>
        </div>
        <div className="bg-dark-950 border border-dark-800 rounded p-3">
          <p className="text-[10px] font-mono uppercase tracking-wider text-dark-500 mb-1">Raw Score</p>
          <p className="text-lg font-mono font-bold text-dark-100">{detail.rawScore.toFixed(3)}</p>
        </div>
        <div className="bg-dark-950 border border-dark-800 rounded p-3">
          <p className="text-[10px] font-mono uppercase tracking-wider text-dark-500 mb-1">Requests</p>
          <p className="text-lg font-mono font-bold text-dark-100">{detail.requestCount}</p>
        </div>
        <div className="bg-dark-950 border border-dark-800 rounded p-3">
          <p className="text-[10px] font-mono uppercase tracking-wider text-dark-500 mb-1">Threats</p>
          <p className="text-lg font-mono font-bold text-red-400">{detail.threatCount}</p>
        </div>
      </div>

      {/* Score bar */}
      <div>
        <div className="flex items-center justify-between mb-1.5">
          <span className="text-[10px] font-mono uppercase tracking-wider text-dark-500">Threat Level</span>
          <span className="text-[10px] font-mono text-dark-400">
            {detail.thresholdExceeded ? 'ABOVE THRESHOLD' : 'Below threshold'}
          </span>
        </div>
        <ScoreBar score={detail.cumulativeScore} threshold={threshold} />
      </div>

      {/* Session info */}
      <div className="bg-dark-950 border border-dark-800 rounded p-3">
        <p className="text-[10px] font-mono uppercase tracking-wider text-dark-500 mb-2">Session Info</p>
        <div className="grid grid-cols-2 gap-2 text-xs font-mono">
          <div>
            <span className="text-dark-500">Session ID: </span>
            <span className="text-dark-300 break-all">{detail.sessionId}</span>
          </div>
          <div>
            <span className="text-dark-500">Authenticated: </span>
            <span className="text-dark-300">{detail.isAuthenticated ? 'Yes' : 'No'}</span>
          </div>
          {detail.userId && (
            <div>
              <span className="text-dark-500">User ID: </span>
              <span className="text-dark-300">{detail.userId}</span>
            </div>
          )}
          <div>
            <span className="text-dark-500">Alert Count: </span>
            <span className="text-dark-300">{detail.alertCount}</span>
          </div>
          {detail.alertTriggeredAt && (
            <div>
              <span className="text-dark-500">Last Alert: </span>
              <span className="text-dark-300">{format(new Date(detail.alertTriggeredAt), 'MMM dd, HH:mm:ss')}</span>
            </div>
          )}
          {detail.lastUpdateTime && (
            <div>
              <span className="text-dark-500">Last Activity: </span>
              <span className="text-dark-300">{format(new Date(detail.lastUpdateTime), 'MMM dd, HH:mm:ss')}</span>
            </div>
          )}
        </div>
      </div>

      {/* Recent history */}
      {detail.recentHistory && detail.recentHistory.length > 0 && (
        <div className="bg-dark-950 border border-dark-800 rounded overflow-hidden">
          <div className="px-3 py-2 border-b border-dark-800">
            <p className="text-[10px] font-mono uppercase tracking-wider text-dark-500">Recent Request History</p>
          </div>
          <div className="divide-y divide-dark-800/50 max-h-64 overflow-y-auto">
            {detail.recentHistory.map((entry, idx) => {
              const actionStyles = {
                blocked: 'bg-red-500/20 text-red-400 border-red-500/30',
                flagged: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
                allowed: 'bg-primary-500/20 text-primary-400 border-primary-500/30',
              };
              return (
                <div key={idx} className="px-3 py-2 flex items-center justify-between gap-3">
                  <div className="flex items-center gap-3 min-w-0">
                    <span className="text-dark-500 text-[10px] font-mono whitespace-nowrap">
                      {entry.timestamp ? format(new Date(entry.timestamp), 'HH:mm:ss') : '--'}
                    </span>
                    <span className={`px-2 py-0.5 text-[10px] font-mono font-medium border ${actionStyles[entry.action] || actionStyles.allowed}`}>
                      {entry.action ? entry.action.toUpperCase() : 'UNKNOWN'}
                    </span>
                    {entry.detectedThreats && entry.detectedThreats.length > 0 && (
                      <span className="text-dark-400 text-[10px] font-mono truncate">
                        {entry.detectedThreats.join(', ')}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    <span className="text-dark-400 text-[10px] font-mono">+{entry.requestThreatScore?.toFixed(2) || '0'}</span>
                    <span className="text-dark-300 text-[10px] font-mono font-bold">{entry.cumulativeScore?.toFixed(2) || '--'}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Actions */}
      <div className="flex gap-3">
        {alertTriggered && (
          <button
            onClick={(e) => { e.stopPropagation(); onResetAlert(sessionId); }}
            disabled={isResetting}
            className="flex items-center gap-2 px-4 py-2.5 rounded bg-dark-800 border border-dark-600 text-dark-300 hover:text-dark-100 hover:border-dark-500 font-mono text-xs uppercase tracking-wider transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-primary-500 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            Reset Alert
          </button>
        )}
        <button
          onClick={(e) => { e.stopPropagation(); onDeleteSession(sessionId); }}
          disabled={isDeleting}
          className="flex items-center gap-2 px-4 py-2.5 rounded bg-dark-800 border border-red-500/30 text-red-400 hover:text-red-300 hover:border-red-500/50 font-mono text-xs uppercase tracking-wider transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-red-500 disabled:opacity-40 disabled:cursor-not-allowed"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
          </svg>
          Delete Session
        </button>
      </div>
    </div>
  );
}

function Sessions() {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const [expandedId, setExpandedId] = useState(null);
  const [deleteConfirm, setDeleteConfirm] = useState({ open: false, sessionId: null });

  const { data, isLoading, error } = useQuery({
    queryKey: ['elevated-sessions'],
    queryFn: async () => {
      const response = await api.get('/api/analytics/sessions/elevated');
      return response.data;
    },
    refetchInterval: 30000,
  });

  const resetAlertMutation = useMutation({
    mutationFn: async (sessionId) => {
      const response = await api.post(`/api/analytics/sessions/${encodeURIComponent(sessionId)}/reset-alert`);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['elevated-sessions'] });
      queryClient.invalidateQueries({ queryKey: ['session-detail'] });
    },
  });

  const deleteSessionMutation = useMutation({
    mutationFn: async (sessionId) => {
      await api.delete(`/api/analytics/sessions/${encodeURIComponent(sessionId)}`);
    },
    onSuccess: () => {
      setExpandedId(null);
      queryClient.invalidateQueries({ queryKey: ['elevated-sessions'] });
    },
  });

  if (user?.role !== 'admin') {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-bold text-dark-100 tracking-tight">Sessions</h1>
        <div className="bg-dark-900 border border-dark-700 rounded p-8 text-center">
          <svg className="mx-auto h-12 w-12 text-red-500/60 mb-4" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z" />
          </svg>
          <p className="text-dark-300 text-lg font-medium font-mono">Admin Access Required</p>
          <p className="text-dark-500 text-sm mt-2">Only administrators can investigate sessions.</p>
        </div>
      </div>
    );
  }

  const sessions = data?.sessions || [];
  const threshold = data?.threshold || 2.0;

  const handleDeleteSession = (sessionId) => {
    setDeleteConfirm({ open: true, sessionId });
  };

  const confirmDelete = () => {
    if (deleteConfirm.sessionId) {
      deleteSessionMutation.mutate(deleteConfirm.sessionId);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-dark-100 tracking-tight">Session Investigation</h1>
        <p className="text-dark-500 text-sm mt-1">
          Elevated threat sessions (threshold: {threshold})
        </p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
        <div className="bg-dark-900 border border-dark-700 p-4">
          <p className="text-dark-500 text-xs font-mono uppercase tracking-wider mb-1">Active Sessions</p>
          <p className="text-2xl font-bold font-mono text-primary-400">{sessions.length}</p>
        </div>
        <div className="bg-dark-900 border border-dark-700 p-4">
          <p className="text-dark-500 text-xs font-mono uppercase tracking-wider mb-1">With Alerts</p>
          <p className="text-2xl font-bold font-mono text-red-400">{sessions.filter(s => s.alertTriggered).length}</p>
        </div>
        <div className="bg-dark-900 border border-dark-700 p-4">
          <p className="text-dark-500 text-xs font-mono uppercase tracking-wider mb-1">Above Threshold</p>
          <p className="text-2xl font-bold font-mono text-amber-400">{sessions.filter(s => s.cumulativeScore >= threshold).length}</p>
        </div>
      </div>

      {/* Sessions list */}
      <div className="bg-dark-900 border border-dark-800 rounded overflow-hidden">
        <div className="px-5 py-4 border-b border-dark-800">
          <h2 className="text-sm font-mono font-semibold text-dark-300 uppercase tracking-wider">
            Elevated Sessions
          </h2>
        </div>

        {isLoading ? (
          <div className="p-12 flex items-center justify-center">
            <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-primary-500" />
          </div>
        ) : error ? (
          <div className="p-8 text-center text-red-400 font-mono text-sm">
            Failed to load sessions: {error.message}
          </div>
        ) : sessions.length === 0 ? (
          <div className="py-16 flex flex-col items-center justify-center gap-4">
            <div className="p-4 rounded-full bg-dark-800 border border-dark-700">
              <svg className="w-8 h-8 text-zinc-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
              </svg>
            </div>
            <p className="text-sm text-zinc-500 font-mono">No elevated threat sessions found.</p>
          </div>
        ) : (
          sessions.map((session) => (
            <SessionRow
              key={session.sessionId}
              session={session}
              threshold={threshold}
              isExpanded={expandedId === session.sessionId}
              onToggle={() => setExpandedId(expandedId === session.sessionId ? null : session.sessionId)}
              onResetAlert={(id) => resetAlertMutation.mutate(id)}
              onDeleteSession={handleDeleteSession}
              isResetting={resetAlertMutation.isPending}
              isDeleting={deleteSessionMutation.isPending}
            />
          ))
        )}
      </div>

      {/* Delete Confirmation */}
      <ConfirmDialog
        isOpen={deleteConfirm.open}
        onClose={() => setDeleteConfirm({ open: false, sessionId: null })}
        onConfirm={confirmDelete}
        title="Delete Session Data"
        message={`Are you sure you want to delete all threat data for session "${deleteConfirm.sessionId}"? This action cannot be undone.`}
        confirmText="Delete"
        cancelText="Cancel"
        variant="danger"
      />
    </div>
  );
}

export default Sessions;
