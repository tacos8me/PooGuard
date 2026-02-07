import { useState, useEffect, useRef, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { format } from 'date-fns';
import api from '../lib/api';
import useFocusTrap from '../hooks/useFocusTrap';
import { useSocket } from '../context/SocketContext';
import { useAuth } from '../context/AuthContext';
import ConfirmDialog from '../components/ConfirmDialog';

// Alert Types
const ALERT_TYPES = [
  { value: 'rate', label: 'Rate Limit' },
  { value: 'threshold', label: 'Threshold' },
  { value: 'pattern', label: 'Pattern' },
  { value: 'session_threat', label: 'Session Threat' },
  { value: 'access_pattern', label: 'Access Pattern' },
  { value: 'repeat_block', label: 'Repeat Block' },
];

const THREAT_TYPES = [
  { value: 'prompt_injection', label: 'Prompt Injection' },
  { value: 'jailbreak', label: 'Jailbreak Attempt' },
  { value: 'pii', label: 'PII Detection' },
  { value: 'all', label: 'All Threats' },
];

// Type color mapping for badges and accents
const TYPE_COLORS = {
  threshold:      { bg: 'bg-cyan-500/15',    text: 'text-cyan-400',    border: 'border-cyan-500/30' },
  rate:           { bg: 'bg-amber-500/15',    text: 'text-amber-400',   border: 'border-amber-500/30' },
  session_threat: { bg: 'bg-red-500/15',      text: 'text-red-400',     border: 'border-red-500/30' },
  access_pattern: { bg: 'bg-purple-500/15',   text: 'text-purple-400',  border: 'border-purple-500/30' },
  config_change:  { bg: 'bg-zinc-500/15',     text: 'text-zinc-400',    border: 'border-zinc-500/30' },
  repeat_block:   { bg: 'bg-orange-500/15',   text: 'text-orange-400',  border: 'border-orange-500/30' },
  pattern:        { bg: 'bg-cyan-500/15',      text: 'text-cyan-400',    border: 'border-cyan-500/30' },
};

function getTypeColor(type) {
  return TYPE_COLORS[type] || TYPE_COLORS.threshold;
}

// Detection threshold constants (moved from Settings)
const DETECTION_CATEGORIES = [
  { key: 'prompt_injection', label: 'Prompt Injection', defaultThreshold: 0.70 },
  { key: 'jailbreak', label: 'Jailbreak', defaultThreshold: 0.70 },
  { key: 'pii', label: 'PII Detection', defaultThreshold: 0.70 },
];

const ACTIONS = [
  { value: 'block', label: 'Block', color: 'red' },
  { value: 'flag', label: 'Flag', color: 'yellow' },
  { value: 'allow', label: 'Allow', color: 'green' },
];

const BORDER_COLORS = {
  prompt_injection: 'border-l-red-500',
  jailbreak: 'border-l-amber-500',
  pii: 'border-l-cyan-500',
};

// Threshold presets calibrated against 294-example benchmark (Feb 2026).
// Model scores are bimodal: 0.0 (no threat) or 0.8-0.95 (threat detected).
const THRESHOLD_PRESETS = {
  high_security: {
    label: 'High Security',
    description: 'Maximize threat detection. May flag ambiguous inputs.',
    thresholds: { prompt_injection: 0.40, jailbreak: 0.40, pii: 0.50 },
    icon: (
      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
      </svg>
    ),
  },
  balanced: {
    label: 'Balanced',
    description: 'Best F1 accuracy (PI=0.79, JB=0.65, PII=0.89, SEM=0.81). Recommended for most deployments.',
    thresholds: { prompt_injection: 0.70, jailbreak: 0.70, pii: 0.70 },
    icon: (
      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 6l3 1m0 0l-3 9a5.002 5.002 0 006.001 0M6 7l3 9M6 7l6-2m6 2l3-1m-3 1l-3 9a5.002 5.002 0 006.001 0M18 7l3 9m-3-9l-6-2m0-2v2m0 16V5m0 16H9m3 0h3" />
      </svg>
    ),
  },
  low_friction: {
    label: 'Low Friction',
    description: 'Minimize false positives (0 FP at these thresholds). Only blocks high-confidence threats.',
    thresholds: { prompt_injection: 0.90, jailbreak: 0.90, pii: 0.90 },
    icon: (
      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
      </svg>
    ),
  },
  custom: {
    label: 'Custom',
    description: 'Manually configured thresholds.',
    thresholds: null,
    icon: (
      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4" />
      </svg>
    ),
  },
};

function getSensitivityLabel(value) {
  if (value < 0.3) return 'Very sensitive - may produce false positives';
  if (value < 0.5) return 'Sensitive - balanced detection';
  if (value < 0.7) return 'Moderate - standard detection';
  if (value < 0.9) return 'Conservative - fewer false positives';
  return 'Very conservative - only high-confidence detections';
}

function getSliderBackground(value) {
  const percent = value * 100;
  if (value < 0.4) {
    return `linear-gradient(to right, #b07d4f 0%, #b07d4f ${percent}%, #352e29 ${percent}%, #352e29 100%)`;
  }
  if (value < 0.7) {
    return `linear-gradient(to right, #b07d4f 0%, #f59e0b ${percent}%, #352e29 ${percent}%, #352e29 100%)`;
  }
  return `linear-gradient(to right, #b07d4f 0%, #f59e0b 50%, #ef4444 ${percent}%, #352e29 ${percent}%, #352e29 100%)`;
}

function getActionColor(action) {
  switch (action) {
    case 'block':
      return 'text-red-400 bg-red-500/10 border-red-500/40';
    case 'flag':
      return 'text-amber-400 bg-amber-500/10 border-amber-500/40';
    case 'allow':
      return 'text-primary-400 bg-primary-500/10 border-primary-500/40';
    default:
      return 'text-dark-400 bg-dark-950 border-dark-700';
  }
}

// ActionButtonGroup component with keyboard navigation
function ActionButtonGroup({ threatKey, currentAction, onActionChange }) {
  const buttonRefs = useRef([]);

  const handleKeyDown = useCallback((event, currentIndex) => {
    let newIndex = currentIndex;

    switch (event.key) {
      case 'ArrowLeft':
      case 'ArrowUp':
        event.preventDefault();
        newIndex = currentIndex === 0 ? ACTIONS.length - 1 : currentIndex - 1;
        break;
      case 'ArrowRight':
      case 'ArrowDown':
        event.preventDefault();
        newIndex = currentIndex === ACTIONS.length - 1 ? 0 : currentIndex + 1;
        break;
      case 'Enter':
      case ' ':
        event.preventDefault();
        onActionChange(threatKey, ACTIONS[currentIndex].value);
        return;
      case 'Home':
        event.preventDefault();
        newIndex = 0;
        break;
      case 'End':
        event.preventDefault();
        newIndex = ACTIONS.length - 1;
        break;
      default:
        return;
    }

    if (buttonRefs.current[newIndex]) {
      buttonRefs.current[newIndex].focus();
    }
  }, [threatKey, onActionChange]);

  return (
    <div
      className="flex gap-1.5"
      role="radiogroup"
      aria-label={`Action for ${threatKey}`}
    >
      {ACTIONS.map((action, index) => (
        <button
          key={action.value}
          ref={(el) => { buttonRefs.current[index] = el; }}
          onClick={() => onActionChange(threatKey, action.value)}
          onKeyDown={(e) => handleKeyDown(e, index)}
          role="radio"
          aria-checked={currentAction === action.value}
          tabIndex={currentAction === action.value ? 0 : -1}
          className={`flex-1 py-1.5 px-2 rounded border transition-all duration-200 font-mono text-[11px] uppercase tracking-wider text-center focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-1 focus:ring-offset-dark-950 ${
            currentAction === action.value
              ? getActionColor(action.value)
              : 'text-dark-500 bg-dark-950 border-dark-700 hover:border-dark-600 hover:text-dark-400'
          }`}
        >
          {action.label}
        </button>
      ))}
    </div>
  );
}

// Reusable type badge component
function TypeBadge({ type, label }) {
  const colors = getTypeColor(type);
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded font-mono text-xs font-medium border ${colors.bg} ${colors.text} ${colors.border}`}>
      {label || type}
    </span>
  );
}

// Validation checkmark icon
function CheckIcon() {
  return (
    <span className="absolute right-3 top-1/2 -translate-y-1/2 text-primary-500">
      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
      </svg>
    </span>
  );
}

// Field validation styling helper
function getFieldClasses(isTouched, hasError, hasValue) {
  if (isTouched && hasError) {
    return 'border-red-500/60 focus:border-red-500 focus:ring-red-500/20';
  }
  if (isTouched && !hasError && hasValue) {
    return 'border-primary-500/40 focus:border-primary-500 focus:ring-primary-500/20';
  }
  return '';
}

// Toast Component
function Toast({ message, type = 'info', onClose }) {
  useEffect(() => {
    const timer = setTimeout(onClose, 5000);
    return () => clearTimeout(timer);
  }, [onClose]);

  let bgColor = 'bg-primary-600/90 border-primary-500/30';
  if (type === 'error') {
    bgColor = 'bg-red-600/90 border-red-500/30';
  } else if (type === 'info') {
    bgColor = 'bg-cyan-600/90 border-cyan-500/30';
  }

  return (
    <div
      className={`fixed top-4 right-4 ${bgColor} border text-white px-5 py-3 rounded-lg shadow-lg z-50 backdrop-blur-sm animate-fade-in`}
      aria-live="polite"
      aria-atomic="true"
      role="status"
    >
      <div className="flex items-center gap-3">
        <svg className="w-4 h-4 opacity-80" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
        </svg>
        <span className="text-sm font-medium">{message}</span>
        <button onClick={onClose} className="ml-2 hover:opacity-75 transition-opacity">
          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>
    </div>
  );
}

// Modal Component with focus trap and keyboard support
function Modal({ isOpen, onClose, title, children, triggerRef }) {
  const titleId = 'modal-title';

  // Use focus trap hook for accessibility
  const modalRef = useFocusTrap(isOpen, {
    onEscape: onClose,
    triggerRef: triggerRef,
  });

  // Handle click on backdrop
  const handleBackdropClick = (e) => {
    // Only close if clicking the backdrop itself, not the modal content
    if (e.target === e.currentTarget) {
      onClose();
    }
  };

  // Handle backdrop keydown (for accessibility)
  const handleBackdropKeyDown = (e) => {
    if (e.key === 'Escape') {
      onClose();
    }
  };

  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 z-50 overflow-y-auto"
      onKeyDown={handleBackdropKeyDown}
    >
      <div
        className="flex items-center justify-center min-h-screen px-4 pt-4 pb-20 text-center sm:p-0"
        onClick={handleBackdropClick}
      >
        <div
          className="fixed inset-0 bg-dark-950/85 backdrop-blur-sm transition-opacity"
          aria-hidden="true"
        />
        <div
          ref={modalRef}
          className="relative inline-block w-full max-w-lg p-6 my-8 overflow-hidden text-left align-middle bg-dark-900 border border-dark-800 rounded-xl shadow-2xl transform transition-all"
          role="dialog"
          aria-modal="true"
          aria-labelledby={titleId}
        >
          <div className="flex items-center justify-between mb-5">
            <h3 id={titleId} className="text-lg font-semibold text-zinc-100 font-mono tracking-tight">{title}</h3>
            <button
              onClick={onClose}
              className="text-zinc-500 hover:text-zinc-300 transition-colors focus:outline-none focus:ring-2 focus:ring-primary-500 rounded p-1"
              aria-label="Close modal"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
          {children}
        </div>
      </div>
    </div>
  );
}

// Stat card used in the summary strip
function StatCard({ label, value, accent }) {
  const accentColors = {
    primary: 'text-primary-400',
    amber: 'text-amber-400',
    cyan: 'text-cyan-400',
    red: 'text-red-400',
  };
  const colorClass = accentColors[accent] || accentColors.primary;

  return (
    <div className="bg-dark-900 border border-dark-800 rounded-lg px-5 py-4 flex flex-col gap-1 min-w-0">
      <span className="text-xs font-medium text-zinc-500 uppercase tracking-wider">{label}</span>
      <span className={`text-2xl font-mono font-bold ${colorClass}`}>{value}</span>
    </div>
  );
}

// Alert Form Component
function AlertForm({ alert, onSave, onCancel, isLoading }) {
  const [formData, setFormData] = useState({
    name: alert?.name || '',
    type: alert?.type || 'rate',
    enabled: alert?.enabled ?? true,
    config: alert?.config || {},
  });
  const [fieldErrors, setFieldErrors] = useState({});
  const [touched, setTouched] = useState({});

  // Validation function for individual fields
  const validateField = (fieldName, value, _allData = formData) => {
    switch (fieldName) {
      case 'name':
        if (!value || !value.trim()) return 'Alert name is required';
        if (value.length < 2) return 'Name must be at least 2 characters';
        if (value.length > 100) return 'Name must be less than 100 characters';
        return '';
      case 'maxCount':
        if (!value || value < 1) return 'Max count must be at least 1';
        if (value > 10000) return 'Max count must be less than 10,000';
        return '';
      case 'windowMinutes':
        if (!value || value < 1) return 'Window must be at least 1 minute';
        if (value > 1440) return 'Window must be less than 24 hours (1440 minutes)';
        return '';
      case 'threshold':
        if (formData.type === 'session_threat') {
          if (!value || value < 0.1) return 'Threshold must be at least 0.1';
          if (value > 10) return 'Threshold must be at most 10';
        } else {
          if (!value || value < 1) return 'Threshold must be at least 1';
        }
        return '';
      case 'thresholdMultiplier':
        if (!value || value < 1) return 'Multiplier must be at least 1.0';
        if (value > 10) return 'Multiplier must be at most 10';
        return '';
      case 'maxBlocks':
        if (!value || value < 1) return 'Max blocks must be at least 1';
        if (value > 100) return 'Max blocks must be at most 100';
        return '';
      case 'pattern':
        if (!value || !value.trim()) return 'Pattern is required';
        // Test if pattern is valid regex
        try {
          new RegExp(value);
          return '';
        } catch {
          return 'Invalid regex pattern';
        }
      default:
        return '';
    }
  };

  // Handle field blur for validation
  const handleBlur = (fieldName, value) => {
    setTouched((prev) => ({ ...prev, [fieldName]: true }));
    setFieldErrors((prev) => ({ ...prev, [fieldName]: validateField(fieldName, value) }));
  };

  // Check if form is valid based on current type
  const isFormValid = () => {
    const nameError = validateField('name', formData.name);
    if (nameError) return false;

    if (formData.type === 'rate') {
      const maxCountError = validateField('maxCount', formData.config.maxCount);
      const windowError = validateField('windowMinutes', formData.config.windowMinutes);
      if (maxCountError || windowError) return false;
    } else if (formData.type === 'threshold') {
      const thresholdError = validateField('threshold', formData.config.threshold);
      if (thresholdError) return false;
    } else if (formData.type === 'pattern') {
      const patternError = validateField('pattern', formData.config.pattern);
      if (patternError) return false;
    } else if (formData.type === 'session_threat') {
      const thresholdError = validateField('threshold', formData.config.threshold);
      if (thresholdError) return false;
    } else if (formData.type === 'access_pattern') {
      const windowError = validateField('windowMinutes', formData.config.windowMinutes);
      const multiplierError = validateField('thresholdMultiplier', formData.config.thresholdMultiplier);
      if (windowError || multiplierError) return false;
    } else if (formData.type === 'repeat_block') {
      const windowError = validateField('windowMinutes', formData.config.windowMinutes);
      const maxBlocksError = validateField('maxBlocks', formData.config.maxBlocks);
      if (windowError || maxBlocksError) return false;
    }

    return true;
  };

  const handleTypeChange = (type) => {
    let defaultConfig = {};
    if (type === 'rate') {
      defaultConfig = { maxCount: 100, windowMinutes: 5 };
    } else if (type === 'threshold') {
      defaultConfig = { threatType: 'all', threshold: 10 };
    } else if (type === 'pattern') {
      defaultConfig = { pattern: '' };
    } else if (type === 'session_threat') {
      defaultConfig = { threshold: 2.0 };
    } else if (type === 'access_pattern') {
      defaultConfig = { windowMinutes: 60, thresholdMultiplier: 3.0 };
    } else if (type === 'repeat_block') {
      defaultConfig = { windowMinutes: 10, maxBlocks: 5 };
    }
    // Reset touched state for config fields when type changes
    setTouched((prev) => ({
      ...prev,
      maxCount: false, windowMinutes: false, threshold: false, pattern: false,
      thresholdMultiplier: false, maxBlocks: false,
    }));
    setFieldErrors((prev) => ({
      ...prev,
      maxCount: '', windowMinutes: '', threshold: '', pattern: '',
      thresholdMultiplier: '', maxBlocks: '',
    }));
    setFormData({ ...formData, type, config: alert?.type === type ? formData.config : defaultConfig });
  };

  const handleConfigChange = (key, value) => {
    setFormData({ ...formData, config: { ...formData.config, [key]: value } });
    // Validate on change if field has been touched
    if (touched[key]) {
      setFieldErrors((prev) => ({ ...prev, [key]: validateField(key, value) }));
    }
  };

  const handleNameChange = (value) => {
    setFormData({ ...formData, name: value });
    if (touched.name) {
      setFieldErrors((prev) => ({ ...prev, name: validateField('name', value) }));
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    onSave(formData);
  };

  const inputBase = 'w-full px-4 py-2.5 bg-dark-950 border border-dark-700 rounded-lg text-zinc-100 placeholder-zinc-600 focus:outline-none focus:ring-2 focus:ring-primary-500/40 focus:border-primary-500/50 transition-all duration-200 font-mono text-sm';
  const labelBase = 'block text-xs font-medium text-zinc-400 mb-1.5 font-mono uppercase tracking-wider';

  return (
    <form onSubmit={handleSubmit} className="space-y-5">
      {/* Alert Name */}
      <div>
        <label htmlFor="alert-name" className={labelBase}>Alert Name</label>
        <div className="relative">
          <input
            id="alert-name"
            type="text"
            className={`${inputBase} ${getFieldClasses(touched.name, fieldErrors.name, formData.name)} !font-sans`}
            placeholder="Enter alert name"
            value={formData.name}
            onChange={(e) => handleNameChange(e.target.value)}
            onBlur={(e) => handleBlur('name', e.target.value)}
            required
            aria-invalid={touched.name && fieldErrors.name ? 'true' : 'false'}
            aria-describedby={fieldErrors.name ? 'name-error' : undefined}
          />
          {touched.name && !fieldErrors.name && formData.name && <CheckIcon />}
        </div>
        {touched.name && fieldErrors.name && (
          <p id="name-error" className="mt-1.5 text-xs text-red-400 font-mono" role="alert">
            {fieldErrors.name}
          </p>
        )}
      </div>

      {/* Alert Type - Grid of badges */}
      <div>
        <label className={labelBase}>Alert Type</label>
        <div className="grid grid-cols-3 gap-2">
          {ALERT_TYPES.map((type) => {
            const colors = getTypeColor(type.value);
            const isSelected = formData.type === type.value;
            return (
              <button
                key={type.value}
                type="button"
                onClick={() => handleTypeChange(type.value)}
                className={`px-3 py-2 rounded-lg text-xs font-mono font-medium border transition-all duration-200 text-center ${
                  isSelected
                    ? `${colors.bg} ${colors.text} ${colors.border} ring-1 ring-current/20`
                    : 'bg-dark-950 border-dark-700 text-zinc-500 hover:text-zinc-300 hover:border-dark-600'
                }`}
              >
                {type.label}
              </button>
            );
          })}
        </div>
        {/* Hidden select for form semantics */}
        <select
          id="alert-type"
          className="sr-only"
          value={formData.type}
          onChange={(e) => handleTypeChange(e.target.value)}
          tabIndex={-1}
          aria-hidden="true"
        >
          {ALERT_TYPES.map((type) => (
            <option key={type.value} value={type.value}>
              {type.label}
            </option>
          ))}
        </select>
      </div>

      {/* Rate Config */}
      {formData.type === 'rate' && (
        <div className="space-y-4 pt-1">
          <div>
            <label htmlFor="max-count" className={labelBase}>Max Count</label>
            <div className="relative">
              <input
                id="max-count"
                type="number"
                className={`${inputBase} ${getFieldClasses(touched.maxCount, fieldErrors.maxCount, formData.config.maxCount)}`}
                placeholder="100"
                value={formData.config.maxCount || ''}
                onChange={(e) => handleConfigChange('maxCount', parseInt(e.target.value) || 0)}
                onBlur={(e) => handleBlur('maxCount', parseInt(e.target.value) || 0)}
                min={1}
                required
                aria-invalid={touched.maxCount && fieldErrors.maxCount ? 'true' : 'false'}
                aria-describedby={fieldErrors.maxCount ? 'maxCount-error' : undefined}
              />
              {touched.maxCount && !fieldErrors.maxCount && formData.config.maxCount && <CheckIcon />}
            </div>
            {touched.maxCount && fieldErrors.maxCount && (
              <p id="maxCount-error" className="mt-1.5 text-xs text-red-400 font-mono" role="alert">
                {fieldErrors.maxCount}
              </p>
            )}
          </div>
          <div>
            <label htmlFor="window-minutes" className={labelBase}>Window (Minutes)</label>
            <div className="relative">
              <input
                id="window-minutes"
                type="number"
                className={`${inputBase} ${getFieldClasses(touched.windowMinutes, fieldErrors.windowMinutes, formData.config.windowMinutes)}`}
                placeholder="5"
                value={formData.config.windowMinutes || ''}
                onChange={(e) => handleConfigChange('windowMinutes', parseInt(e.target.value) || 0)}
                onBlur={(e) => handleBlur('windowMinutes', parseInt(e.target.value) || 0)}
                min={1}
                required
                aria-invalid={touched.windowMinutes && fieldErrors.windowMinutes ? 'true' : 'false'}
                aria-describedby={fieldErrors.windowMinutes ? 'windowMinutes-error' : undefined}
              />
              {touched.windowMinutes && !fieldErrors.windowMinutes && formData.config.windowMinutes && <CheckIcon />}
            </div>
            {touched.windowMinutes && fieldErrors.windowMinutes && (
              <p id="windowMinutes-error" className="mt-1.5 text-xs text-red-400 font-mono" role="alert">
                {fieldErrors.windowMinutes}
              </p>
            )}
          </div>
        </div>
      )}

      {/* Threshold Config */}
      {formData.type === 'threshold' && (
        <div className="space-y-4 pt-1">
          <div>
            <label htmlFor="threat-type" className={labelBase}>Threat Type</label>
            <select
              id="threat-type"
              className={`${inputBase} cursor-pointer`}
              value={formData.config.threatType || 'all'}
              onChange={(e) => handleConfigChange('threatType', e.target.value)}
            >
              {THREAT_TYPES.map((type) => (
                <option key={type.value} value={type.value}>
                  {type.label}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="threshold-value" className={labelBase}>Threshold Value</label>
            <div className="relative">
              <input
                id="threshold-value"
                type="number"
                className={`${inputBase} ${getFieldClasses(touched.threshold, fieldErrors.threshold, formData.config.threshold)}`}
                placeholder="10"
                value={formData.config.threshold || ''}
                onChange={(e) => handleConfigChange('threshold', parseInt(e.target.value) || 0)}
                onBlur={(e) => handleBlur('threshold', parseInt(e.target.value) || 0)}
                min={1}
                required
                aria-invalid={touched.threshold && fieldErrors.threshold ? 'true' : 'false'}
                aria-describedby={fieldErrors.threshold ? 'threshold-error' : undefined}
              />
              {touched.threshold && !fieldErrors.threshold && formData.config.threshold && <CheckIcon />}
            </div>
            {touched.threshold && fieldErrors.threshold && (
              <p id="threshold-error" className="mt-1.5 text-xs text-red-400 font-mono" role="alert">
                {fieldErrors.threshold}
              </p>
            )}
          </div>
        </div>
      )}

      {/* Pattern Config */}
      {formData.type === 'pattern' && (
        <div className="pt-1">
          <label htmlFor="pattern-regex" className={labelBase}>Pattern (Regex)</label>
          <div className="relative">
            <input
              id="pattern-regex"
              type="text"
              className={`${inputBase} ${getFieldClasses(touched.pattern, fieldErrors.pattern, formData.config.pattern)}`}
              placeholder="Enter regex pattern"
              value={formData.config.pattern || ''}
              onChange={(e) => handleConfigChange('pattern', e.target.value)}
              onBlur={(e) => handleBlur('pattern', e.target.value)}
              required
              aria-invalid={touched.pattern && fieldErrors.pattern ? 'true' : 'false'}
              aria-describedby={fieldErrors.pattern ? 'pattern-error' : undefined}
            />
            {touched.pattern && !fieldErrors.pattern && formData.config.pattern && <CheckIcon />}
          </div>
          {touched.pattern && fieldErrors.pattern && (
            <p id="pattern-error" className="mt-1.5 text-xs text-red-400 font-mono" role="alert">
              {fieldErrors.pattern}
            </p>
          )}
        </div>
      )}

      {/* Session Threat Config */}
      {formData.type === 'session_threat' && (
        <div className="pt-1">
          <label htmlFor="session-threshold" className={labelBase}>Score Threshold</label>
          <div className="relative">
            <input
              id="session-threshold"
              type="number"
              className={`${inputBase} ${getFieldClasses(touched.threshold, fieldErrors.threshold, formData.config.threshold)}`}
              value={formData.config.threshold || ''}
              onChange={(e) => handleConfigChange('threshold', parseFloat(e.target.value))}
              onBlur={(e) => handleBlur('threshold', parseFloat(e.target.value))}
              placeholder="e.g., 2.0"
              step="0.1"
              min="0.1"
              max="10"
              required
              aria-invalid={touched.threshold && fieldErrors.threshold ? 'true' : 'false'}
              aria-describedby={fieldErrors.threshold ? 'session-threshold-error' : undefined}
            />
            {touched.threshold && !fieldErrors.threshold && formData.config.threshold && <CheckIcon />}
          </div>
          {touched.threshold && fieldErrors.threshold && (
            <p id="session-threshold-error" className="mt-1.5 text-xs text-red-400 font-mono" role="alert">
              {fieldErrors.threshold}
            </p>
          )}
          <p className="text-zinc-600 text-xs mt-1.5 font-mono">Alert when session cumulative threat score exceeds this value</p>
        </div>
      )}

      {/* Access Pattern Config */}
      {formData.type === 'access_pattern' && (
        <div className="space-y-4 pt-1">
          <div>
            <label htmlFor="access-window" className={labelBase}>Window (minutes)</label>
            <div className="relative">
              <input
                id="access-window"
                type="number"
                className={`${inputBase} ${getFieldClasses(touched.windowMinutes, fieldErrors.windowMinutes, formData.config.windowMinutes)}`}
                value={formData.config.windowMinutes || ''}
                onChange={(e) => handleConfigChange('windowMinutes', parseInt(e.target.value) || 0)}
                onBlur={(e) => handleBlur('windowMinutes', parseInt(e.target.value) || 0)}
                placeholder="e.g., 60"
                min="5"
                max="1440"
                required
                aria-invalid={touched.windowMinutes && fieldErrors.windowMinutes ? 'true' : 'false'}
                aria-describedby={fieldErrors.windowMinutes ? 'access-window-error' : undefined}
              />
              {touched.windowMinutes && !fieldErrors.windowMinutes && formData.config.windowMinutes && <CheckIcon />}
            </div>
            {touched.windowMinutes && fieldErrors.windowMinutes && (
              <p id="access-window-error" className="mt-1.5 text-xs text-red-400 font-mono" role="alert">
                {fieldErrors.windowMinutes}
              </p>
            )}
            <p className="text-zinc-600 text-xs mt-1.5 font-mono">Time window to analyze access patterns</p>
          </div>
          <div>
            <label htmlFor="threshold-multiplier" className={labelBase}>Threshold Multiplier</label>
            <div className="relative">
              <input
                id="threshold-multiplier"
                type="number"
                className={`${inputBase} ${getFieldClasses(touched.thresholdMultiplier, fieldErrors.thresholdMultiplier, formData.config.thresholdMultiplier)}`}
                value={formData.config.thresholdMultiplier || ''}
                onChange={(e) => handleConfigChange('thresholdMultiplier', parseFloat(e.target.value))}
                onBlur={(e) => handleBlur('thresholdMultiplier', parseFloat(e.target.value))}
                placeholder="e.g., 2.0"
                step="0.1"
                min="1.0"
                max="10"
                required
                aria-invalid={touched.thresholdMultiplier && fieldErrors.thresholdMultiplier ? 'true' : 'false'}
                aria-describedby={fieldErrors.thresholdMultiplier ? 'multiplier-error' : undefined}
              />
              {touched.thresholdMultiplier && !fieldErrors.thresholdMultiplier && formData.config.thresholdMultiplier && <CheckIcon />}
            </div>
            {touched.thresholdMultiplier && fieldErrors.thresholdMultiplier && (
              <p id="multiplier-error" className="mt-1.5 text-xs text-red-400 font-mono" role="alert">
                {fieldErrors.thresholdMultiplier}
              </p>
            )}
            <p className="text-zinc-600 text-xs mt-1.5 font-mono">Multiplier above baseline to trigger alert</p>
          </div>
        </div>
      )}

      {/* Repeat Block Config */}
      {formData.type === 'repeat_block' && (
        <div className="space-y-4 pt-1">
          <div>
            <label htmlFor="repeat-window" className={labelBase}>Window (minutes)</label>
            <div className="relative">
              <input
                id="repeat-window"
                type="number"
                className={`${inputBase} ${getFieldClasses(touched.windowMinutes, fieldErrors.windowMinutes, formData.config.windowMinutes)}`}
                value={formData.config.windowMinutes || ''}
                onChange={(e) => handleConfigChange('windowMinutes', parseInt(e.target.value) || 0)}
                onBlur={(e) => handleBlur('windowMinutes', parseInt(e.target.value) || 0)}
                placeholder="e.g., 10"
                min="1"
                max="1440"
                required
                aria-invalid={touched.windowMinutes && fieldErrors.windowMinutes ? 'true' : 'false'}
                aria-describedby={fieldErrors.windowMinutes ? 'repeat-window-error' : undefined}
              />
              {touched.windowMinutes && !fieldErrors.windowMinutes && formData.config.windowMinutes && <CheckIcon />}
            </div>
            {touched.windowMinutes && fieldErrors.windowMinutes && (
              <p id="repeat-window-error" className="mt-1.5 text-xs text-red-400 font-mono" role="alert">
                {fieldErrors.windowMinutes}
              </p>
            )}
          </div>
          <div>
            <label htmlFor="max-blocks" className={labelBase}>Max Blocks Before Alert</label>
            <div className="relative">
              <input
                id="max-blocks"
                type="number"
                className={`${inputBase} ${getFieldClasses(touched.maxBlocks, fieldErrors.maxBlocks, formData.config.maxBlocks)}`}
                value={formData.config.maxBlocks || ''}
                onChange={(e) => handleConfigChange('maxBlocks', parseInt(e.target.value) || 0)}
                onBlur={(e) => handleBlur('maxBlocks', parseInt(e.target.value) || 0)}
                placeholder="e.g., 5"
                min="1"
                max="100"
                required
                aria-invalid={touched.maxBlocks && fieldErrors.maxBlocks ? 'true' : 'false'}
                aria-describedby={fieldErrors.maxBlocks ? 'maxBlocks-error' : undefined}
              />
              {touched.maxBlocks && !fieldErrors.maxBlocks && formData.config.maxBlocks && <CheckIcon />}
            </div>
            {touched.maxBlocks && fieldErrors.maxBlocks && (
              <p id="maxBlocks-error" className="mt-1.5 text-xs text-red-400 font-mono" role="alert">
                {fieldErrors.maxBlocks}
              </p>
            )}
            <p className="text-zinc-600 text-xs mt-1.5 font-mono">Number of blocks from same source to trigger alert</p>
          </div>
        </div>
      )}

      {/* Form actions */}
      <div className="flex gap-3 pt-5 border-t border-dark-800">
        <button
          type="submit"
          className="flex-1 px-4 py-2.5 rounded-lg font-medium text-sm transition-all duration-200 bg-primary-600 hover:bg-primary-500 text-white focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 focus:ring-offset-dark-900 disabled:opacity-40 disabled:cursor-not-allowed"
          disabled={isLoading || !isFormValid()}
        >
          {isLoading ? 'Saving...' : 'Save Alert'}
        </button>
        <button
          type="button"
          className="flex-1 px-4 py-2.5 rounded-lg font-medium text-sm transition-all duration-200 bg-dark-800 hover:bg-dark-700 text-zinc-300 border border-dark-700 focus:outline-none focus:ring-2 focus:ring-dark-500 focus:ring-offset-2 focus:ring-offset-dark-900"
          onClick={onCancel}
          disabled={isLoading}
        >
          Cancel
        </button>
      </div>
    </form>
  );
}

// Expandable trigger row for alert history
function TriggerRow({ trigger, onAcknowledge, isAcknowledging }) {
  const [expanded, setExpanded] = useState(false);

  const alertType = trigger.alert_type || trigger.alertType || trigger.type || 'threshold';
  const hasData = trigger.data && (typeof trigger.data === 'string' ? trigger.data.length > 0 : Object.keys(trigger.data).length > 0);

  // Severity based on acknowledgement: unacknowledged = critical (red), acknowledged = neutral
  const severityBorder = trigger.acknowledged ? 'border-l-zinc-700' : 'border-l-red-500';

  return (
    <div className={`border-l-2 ${severityBorder} transition-colors`}>
      <div
        className="px-4 py-3.5 hover:bg-dark-800/50 transition-colors cursor-pointer"
        onClick={() => hasData && setExpanded(!expanded)}
        onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); hasData && setExpanded(!expanded); } }}
        role={hasData ? 'button' : undefined}
        tabIndex={hasData ? 0 : undefined}
        aria-expanded={hasData ? expanded : undefined}
      >
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3 flex-wrap">
              <h3 className="font-medium text-zinc-200 text-sm">{trigger.alert_name || trigger.alertName || trigger.name || 'Alert'}</h3>
              <TypeBadge type={alertType} label={ALERT_TYPES.find((t) => t.value === alertType)?.label || alertType} />
              {trigger.acknowledged ? (
                <span className="px-2 py-0.5 text-xs font-mono bg-dark-800 text-zinc-500 rounded border border-dark-700">
                  ACK
                </span>
              ) : (
                <span className="px-2 py-0.5 text-xs font-mono bg-red-500/10 text-red-400 rounded border border-red-500/20 animate-pulse">
                  OPEN
                </span>
              )}
              {hasData && (
                <svg className={`w-3.5 h-3.5 text-zinc-600 transition-transform duration-200 ${expanded ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
              )}
            </div>
            <p className="text-xs text-zinc-500 mt-1.5 font-mono">
              {(trigger.triggered_at || trigger.triggeredAt) ? format(new Date(trigger.triggered_at || trigger.triggeredAt), 'PPpp') : 'Unknown'}
            </p>
          </div>
          {!trigger.acknowledged && (
            <button
              onClick={(e) => { e.stopPropagation(); onAcknowledge(trigger.id); }}
              className="shrink-0 px-3 py-1.5 rounded-md text-xs font-mono font-medium transition-all duration-200 bg-dark-800 hover:bg-dark-700 text-zinc-400 hover:text-zinc-200 border border-dark-700 hover:border-dark-600 focus:outline-none focus:ring-2 focus:ring-primary-500"
              disabled={isAcknowledging}
            >
              Acknowledge
            </button>
          )}
        </div>
      </div>
      {expanded && hasData && (
        <div className="px-4 pb-4 animate-fade-in">
          <div className="p-3 bg-dark-950 rounded-lg border border-dark-800 text-xs text-zinc-400 font-mono overflow-x-auto whitespace-pre-wrap leading-relaxed">
            {typeof trigger.data === 'string' ? trigger.data : JSON.stringify(trigger.data, null, 2)}
          </div>
        </div>
      )}
    </div>
  );
}

// Empty state component
function EmptyState({ message, onAction, actionLabel }) {
  return (
    <div className="py-16 flex flex-col items-center justify-center gap-4">
      {/* Shield icon */}
      <div className="p-4 rounded-full bg-dark-800 border border-dark-700">
        <svg className="w-8 h-8 text-zinc-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
        </svg>
      </div>
      <p className="text-sm text-zinc-500 font-mono">{message}</p>
      {onAction && actionLabel && (
        <button
          onClick={onAction}
          className="mt-1 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 bg-primary-600 hover:bg-primary-500 text-white focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 focus:ring-offset-dark-950"
        >
          {actionLabel}
        </button>
      )}
    </div>
  );
}

// Main Alerts Component
function Alerts() {
  const { socket } = useSocket();
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingAlert, setEditingAlert] = useState(null);
  const [toast, setToast] = useState(null);
  const [triggerFilter, setTriggerFilter] = useState('all');
  const [deleteConfirm, setDeleteConfirm] = useState({ open: false, alertId: null, alertName: '' });

  // Detection rules state
  const [thresholds, setThresholds] = useState({
    prompt_injection: 0.70,
    jailbreak: 0.70,
    pii: 0.70,
  });
  const [actions, setActions] = useState({
    prompt_injection: 'block',
    jailbreak: 'block',
    pii: 'flag',
  });
  const [selectedPreset, setSelectedPreset] = useState('custom');
  const [hasDetectionChanges, setHasDetectionChanges] = useState(false);
  const [showSaveConfirm, setShowSaveConfirm] = useState(false);

  // Refs for focus management
  const createButtonRef = useRef(null);
  const editButtonRefs = useRef({});
  const deleteButtonRefs = useRef({});

  // Fetch alert rules
  const { data: alertRules = [], isLoading: rulesLoading } = useQuery({
    queryKey: ['alerts'],
    queryFn: async () => {
      const response = await api.get('/api/alerts');
      return response.data.alerts || [];
    },
  });

  // Fetch triggered alerts
  const { data: triggeredAlerts = [], isLoading: triggersLoading } = useQuery({
    queryKey: ['alerts', 'triggers'],
    queryFn: async () => {
      const response = await api.get('/api/alerts/triggers');
      return response.data.triggers || [];
    },
  });

  // Fetch firewall config for detection thresholds
  const { data: firewallConfig } = useQuery({
    queryKey: ['firewallConfig'],
    queryFn: async () => {
      const response = await api.get('/api/firewall/config');
      return response.data;
    },
  });

  // Populate detection state from config
  useEffect(() => {
    if (firewallConfig) {
      const loadedThresholds = {
        prompt_injection: firewallConfig.thresholds?.promptInjection ?? 0.70,
        jailbreak: firewallConfig.thresholds?.jailbreak ?? 0.70,
        pii: firewallConfig.thresholds?.pii ?? 0.70,
      };
      setThresholds(loadedThresholds);
      setActions({
        prompt_injection: firewallConfig.actions?.promptInjection ?? 'block',
        jailbreak: firewallConfig.actions?.jailbreak ?? 'block',
        pii: firewallConfig.actions?.pii ?? 'flag',
      });
      const matchedPreset = Object.entries(THRESHOLD_PRESETS).find(([, preset]) => {
        if (!preset.thresholds) return false;
        return Object.keys(preset.thresholds).every(
          (k) => Math.abs((preset.thresholds[k] || 0) - (loadedThresholds[k] || 0)) < 0.005
        );
      });
      setSelectedPreset(matchedPreset ? matchedPreset[0] : 'custom');
      setHasDetectionChanges(false);
    }
  }, [firewallConfig]);

  // Save detection rules mutation
  const saveDetectionMutation = useMutation({
    mutationFn: async ({ thresholds: t, actions: a }) => {
      const payload = {
        thresholds: {
          promptInjection: t.prompt_injection,
          jailbreak: t.jailbreak,
          pii: t.pii,
        },
        actions: {
          promptInjection: a.prompt_injection,
          jailbreak: a.jailbreak,
          pii: a.pii,
        },
        // Pass through other config fields unchanged
        modelConfig: firewallConfig?.modelConfig
          ? { ...firewallConfig.modelConfig, apiKey: '__UNCHANGED__' }
          : { providerType: 'none', endpointUrl: '', apiKey: '__UNCHANGED__', modelName: '' },
        safeguardModel: firewallConfig?.safeguardModel || '20b',
        dataRetentionDays: firewallConfig?.dataRetentionDays ?? 90,
        failMode: firewallConfig?.failMode || 'open',
        analysisMode: firewallConfig?.analysisMode || 'sync',
      };
      const response = await api.put('/api/firewall/config', payload);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firewallConfig'] });
      setHasDetectionChanges(false);
      setToast({ message: 'Detection rules saved', type: 'success' });
    },
    onError: (error) => {
      setToast({ message: error.response?.data?.error || 'Failed to save detection rules', type: 'error' });
    },
  });

  const handlePresetChange = (presetKey) => {
    setSelectedPreset(presetKey);
    const preset = THRESHOLD_PRESETS[presetKey];
    if (preset?.thresholds) {
      setThresholds({ ...preset.thresholds });
      setHasDetectionChanges(true);
    }
  };

  const handleThresholdChange = (key, value) => {
    setThresholds((prev) => ({ ...prev, [key]: value }));
    setSelectedPreset('custom');
    setHasDetectionChanges(true);
  };

  const handleActionChange = (key, value) => {
    setActions((prev) => ({ ...prev, [key]: value }));
    setHasDetectionChanges(true);
  };

  const handleSaveDetection = () => {
    saveDetectionMutation.mutate({ thresholds, actions });
  };

  // Create alert mutation
  const createAlert = useMutation({
    mutationFn: async (data) => {
      const response = await api.post('/api/alerts', data);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
      setIsModalOpen(false);
      setEditingAlert(null);
      setToast({ message: 'Alert created successfully', type: 'success' });
    },
    onError: (error) => {
      setToast({ message: error.response?.data?.detail || 'Failed to create alert', type: 'error' });
    },
  });

  // Update alert mutation
  const updateAlert = useMutation({
    mutationFn: async ({ id, data }) => {
      const response = await api.put(`/api/alerts/${id}`, data);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
      setIsModalOpen(false);
      setEditingAlert(null);
      setToast({ message: 'Alert updated successfully', type: 'success' });
    },
    onError: (error) => {
      setToast({ message: error.response?.data?.detail || 'Failed to update alert', type: 'error' });
    },
  });

  // Delete alert mutation
  const deleteAlert = useMutation({
    mutationFn: async (id) => {
      await api.delete(`/api/alerts/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
      setToast({ message: 'Alert deleted successfully', type: 'success' });
    },
    onError: (error) => {
      setToast({ message: error.response?.data?.detail || 'Failed to delete alert', type: 'error' });
    },
  });

  // Toggle alert enabled state
  const toggleAlert = useMutation({
    mutationFn: async ({ id, enabled }) => {
      const response = await api.put(`/api/alerts/${id}`, { enabled });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
    },
    onError: (error) => {
      setToast({ message: error.response?.data?.detail || 'Failed to toggle alert', type: 'error' });
    },
  });

  // Acknowledge trigger mutation
  const acknowledgeTrigger = useMutation({
    mutationFn: async (id) => {
      const response = await api.post(`/api/alerts/triggers/${id}/acknowledge`);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts', 'triggers'] });
      setToast({ message: 'Alert acknowledged', type: 'success' });
    },
    onError: (error) => {
      setToast({ message: error.response?.data?.detail || 'Failed to acknowledge alert', type: 'error' });
    },
  });

  // WebSocket event listener using shared socket context
  useEffect(() => {
    if (!socket) return;

    const handleAlertTriggered = (data) => {
      // Show toast notification
      setToast({ message: `Alert triggered: ${data.name || 'New Alert'}`, type: 'info' });
      // Refresh triggered alerts list
      queryClient.invalidateQueries({ queryKey: ['alerts', 'triggers'] });
    };

    socket.on('alert:triggered', handleAlertTriggered);

    return () => {
      socket.off('alert:triggered', handleAlertTriggered);
    };
  }, [socket, queryClient]);

  const handleSaveAlert = (data) => {
    if (editingAlert) {
      updateAlert.mutate({ id: editingAlert.id, data });
    } else {
      createAlert.mutate(data);
    }
  };

  const handleEditAlert = (alert, buttonRef) => {
    setEditingAlert(alert);
    // Store the ref for this specific alert for focus return
    editButtonRefs.current[alert.id] = buttonRef;
    setIsModalOpen(true);
  };

  const handleDeleteAlert = (id, name, buttonRef) => {
    deleteButtonRefs.current[id] = buttonRef;
    setDeleteConfirm({ open: true, alertId: id, alertName: name });
  };

  const confirmDelete = () => {
    if (deleteConfirm.alertId) {
      deleteAlert.mutate(deleteConfirm.alertId);
    }
  };

  const handleCloseModal = () => {
    setIsModalOpen(false);
    setEditingAlert(null);
  };

  const filteredTriggers = triggerFilter === 'unacknowledged'
    ? triggeredAlerts.filter((t) => !t.acknowledged)
    : triggeredAlerts;

  const getTypeLabel = (type) => ALERT_TYPES.find((t) => t.value === type)?.label || type;

  // Compute stats
  const totalRules = alertRules.length;
  const activeRules = alertRules.filter((r) => r.enabled).length;
  const totalTriggers = triggeredAlerts.length;
  const unacknowledgedCount = triggeredAlerts.filter((t) => !t.acknowledged).length;

  // Config summary for each rule
  function getConfigSummary(rule) {
    if (!rule.config) return null;
    switch (rule.type) {
      case 'rate':
        return `${rule.config.maxCount} / ${rule.config.windowMinutes}min`;
      case 'threshold':
        return `${rule.config.threatType}: ${rule.config.threshold}`;
      case 'pattern':
        return rule.config.pattern;
      case 'session_threat':
        return `score > ${rule.config.threshold}`;
      case 'access_pattern':
        return `${rule.config.thresholdMultiplier}x / ${rule.config.windowMinutes}min`;
      case 'repeat_block':
        return `${rule.config.maxBlocks} blocks / ${rule.config.windowMinutes}min`;
      default:
        return null;
    }
  }

  return (
    <div className="space-y-6">
      {/* Toast Notification */}
      {toast && (
        <Toast
          message={toast.message}
          type={toast.type}
          onClose={() => setToast(null)}
        />
      )}

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-dark-100 tracking-tight">Rules</h1>
          <p className="text-dark-500 text-sm mt-1">Detection thresholds, response actions, and alert rules</p>
        </div>
        <div className="flex items-center gap-3">
          {user?.role === 'admin' && (
            <button
              onClick={() => setShowSaveConfirm(true)}
              disabled={!hasDetectionChanges || saveDetectionMutation.isPending}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-lg font-mono text-xs uppercase tracking-wider transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 focus:ring-offset-dark-950 ${
                hasDetectionChanges && !saveDetectionMutation.isPending
                  ? 'bg-primary-600 hover:bg-primary-500 text-white shadow-glow-green-sm hover:shadow-glow-green'
                  : 'bg-dark-700 text-dark-500 cursor-not-allowed'
              }`}
            >
              {saveDetectionMutation.isPending ? (
                <>
                  <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                  Saving...
                </>
              ) : (
                <>
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                  Save Detection Rules
                </>
              )}
            </button>
          )}
          <button
            ref={createButtonRef}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg font-medium text-sm transition-all duration-200 border border-dark-600 bg-dark-800 text-dark-300 hover:text-dark-100 hover:border-dark-500 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 focus:ring-offset-dark-950"
            onClick={() => setIsModalOpen(true)}
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
            </svg>
            Create Alert
          </button>
        </div>
      </div>

      {/* Stats Strip */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <StatCard label="Total Rules" value={totalRules} accent="cyan" />
        <StatCard label="Active Rules" value={activeRules} accent="primary" />
        <StatCard label="Triggered" value={totalTriggers} accent="amber" />
        <StatCard label="Unacknowledged" value={unacknowledgedCount} accent="red" />
      </div>

      {/* Detection Rules Section */}
      {user?.role === 'admin' && (
        <div className="space-y-4">
          {/* Threshold Presets — single row */}
          <div className="flex items-center gap-3">
            <span className="text-[10px] font-mono uppercase tracking-widest text-dark-500 shrink-0">Preset</span>
            <div className="flex gap-2 flex-1">
              {Object.entries(THRESHOLD_PRESETS).map(([key, preset]) => (
                <button
                  key={key}
                  onClick={() => handlePresetChange(key)}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded border transition-all duration-200 font-mono text-xs tracking-wider focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-1 focus:ring-offset-dark-950 ${
                    selectedPreset === key
                      ? 'border-primary-500/40 bg-primary-500/10 text-primary-400'
                      : 'border-dark-700 bg-dark-950 text-dark-400 hover:border-dark-600 hover:text-dark-300'
                  }`}
                  title={preset.description}
                >
                  <span className={selectedPreset === key ? 'text-primary-400' : 'text-dark-500'}>
                    {preset.icon}
                  </span>
                  {preset.label}
                </button>
              ))}
            </div>
          </div>

          {/* Detection Rules — 3 columns */}
          <div className="grid md:grid-cols-3 gap-3">
            {DETECTION_CATEGORIES.map((threat) => {
              const value = Number(thresholds[threat.key] ?? threat.defaultThreshold);
              return (
                <div
                  key={threat.key}
                  className={`bg-dark-900 border border-dark-700 border-l-4 ${BORDER_COLORS[threat.key]} rounded p-4 space-y-3`}
                >
                  <div className="flex items-center justify-between">
                    <label className="text-xs font-mono uppercase tracking-widest text-dark-400">
                      {threat.label}
                    </label>
                    <span className="text-lg font-mono text-dark-100 tabular-nums">
                      {value.toFixed(2)}
                    </span>
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-mono text-dark-600">0</span>
                      <input
                        type="range"
                        min="0"
                        max="1"
                        step="0.01"
                        value={value}
                        onChange={(e) => handleThresholdChange(threat.key, parseFloat(e.target.value))}
                        className="flex-1 h-1.5 rounded-full appearance-none cursor-pointer slider"
                        style={{ background: getSliderBackground(value) }}
                        aria-valuemin={0}
                        aria-valuemax={1}
                        aria-valuenow={value}
                        aria-valuetext={`${(value * 100).toFixed(0)}%`}
                        aria-label={`${threat.label} detection threshold`}
                      />
                      <span className="text-[10px] font-mono text-dark-600">1</span>
                    </div>
                    <p className="text-[10px] text-dark-500 mt-1 font-mono">
                      {getSensitivityLabel(value)}
                    </p>
                  </div>

                  <ActionButtonGroup
                    threatKey={threat.key}
                    currentAction={actions[threat.key]}
                    onActionChange={handleActionChange}
                  />
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Save Detection Confirm Dialog */}
      <ConfirmDialog
        isOpen={showSaveConfirm}
        onClose={() => setShowSaveConfirm(false)}
        onConfirm={() => {
          setShowSaveConfirm(false);
          handleSaveDetection();
        }}
        title="Save Detection Rules"
        message="This will update firewall detection thresholds and response actions for all incoming requests. Changes take effect immediately."
        variant="warning"
        confirmText="Save Changes"
      />

      {/* Alert Rules Section */}
      <div className="bg-dark-900 rounded-xl border border-dark-800 overflow-hidden">
        <div className="px-5 py-4 border-b border-dark-800">
          <h2 className="text-sm font-semibold text-zinc-300 uppercase tracking-wider font-mono">Alert Rules</h2>
        </div>

        {rulesLoading ? (
          <div className="px-5 py-12 text-center">
            <div className="inline-flex items-center gap-2 text-zinc-500 font-mono text-sm">
              <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
              </svg>
              Loading rules...
            </div>
          </div>
        ) : alertRules.length === 0 ? (
          <EmptyState
            message="No alerts configured"
            onAction={() => setIsModalOpen(true)}
            actionLabel="Create Alert"
          />
        ) : (
          <div className="divide-y divide-dark-800">
            {alertRules.map((rule) => {
              const configSummary = getConfigSummary(rule);
              return (
                <div
                  key={rule.id}
                  className={`px-5 py-4 flex items-center justify-between transition-colors hover:bg-dark-800/40 border-l-2 ${
                    rule.enabled ? 'border-l-primary-500' : 'border-l-zinc-700 opacity-70'
                  }`}
                >
                  <div className="flex items-center gap-4 min-w-0 flex-1">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-3 flex-wrap">
                        <h3 className="font-medium text-zinc-200 text-sm truncate">{rule.name}</h3>
                        <TypeBadge type={rule.type} label={getTypeLabel(rule.type)} />
                      </div>
                      {configSummary && (
                        <p className="text-xs text-zinc-600 mt-1.5 font-mono truncate">{configSummary}</p>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0 ml-4">
                    {/* Toggle Switch */}
                    <button
                      onClick={() => toggleAlert.mutate({ id: rule.id, enabled: !rule.enabled })}
                      className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 focus:ring-offset-dark-900 ${
                        rule.enabled ? 'bg-primary-600' : 'bg-zinc-700'
                      }`}
                      disabled={toggleAlert.isPending}
                      role="switch"
                      aria-checked={rule.enabled}
                      aria-label={`${rule.enabled ? 'Disable' : 'Enable'} alert rule ${rule.name}`}
                    >
                      <span
                        className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform duration-200 ${
                          rule.enabled ? 'translate-x-[18px]' : 'translate-x-[3px]'
                        }`}
                      />
                    </button>

                    {/* Edit Button */}
                    <button
                      ref={(el) => { editButtonRefs.current[rule.id] = { current: el }; }}
                      onClick={(e) => handleEditAlert(rule, { current: e.currentTarget })}
                      className="p-1.5 text-zinc-600 hover:text-zinc-300 hover:bg-dark-800 rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-primary-500"
                      title="Edit"
                      aria-label={`Edit alert rule ${rule.name}`}
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                      </svg>
                    </button>

                    {/* Delete Button */}
                    <button
                      onClick={(e) => handleDeleteAlert(rule.id, rule.name, { current: e.currentTarget })}
                      className="p-1.5 text-zinc-600 hover:text-red-400 hover:bg-red-500/10 rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-red-500"
                      title="Delete"
                      aria-label={`Delete alert rule ${rule.name}`}
                      disabled={deleteAlert.isPending}
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                      </svg>
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Alert History Section */}
      <div className="bg-dark-900 rounded-xl border border-dark-800 overflow-hidden">
        <div className="px-5 py-4 border-b border-dark-800 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-zinc-300 uppercase tracking-wider font-mono">Alert History</h2>
          <select
            className="px-3 py-1.5 bg-dark-950 border border-dark-700 rounded-md text-xs text-zinc-400 font-mono focus:outline-none focus:ring-2 focus:ring-primary-500/40 focus:border-primary-500/50 cursor-pointer"
            value={triggerFilter}
            onChange={(e) => setTriggerFilter(e.target.value)}
            aria-label="Filter alert history"
          >
            <option value="all">All Alerts</option>
            <option value="unacknowledged">Unacknowledged Only</option>
          </select>
        </div>

        {triggersLoading ? (
          <div className="px-5 py-12 text-center">
            <div className="inline-flex items-center gap-2 text-zinc-500 font-mono text-sm">
              <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
              </svg>
              Loading history...
            </div>
          </div>
        ) : filteredTriggers.length === 0 ? (
          <EmptyState
            message={triggerFilter === 'unacknowledged' ? 'No unacknowledged alerts' : 'No alerts have been triggered yet'}
          />
        ) : (
          <div className="divide-y divide-dark-800">
            {filteredTriggers.map((trigger) => (
              <TriggerRow
                key={trigger.id}
                trigger={trigger}
                onAcknowledge={(id) => acknowledgeTrigger.mutate(id)}
                isAcknowledging={acknowledgeTrigger.isPending}
              />
            ))}
          </div>
        )}
      </div>

      {/* Create/Edit Modal */}
      <Modal
        isOpen={isModalOpen}
        onClose={handleCloseModal}
        title={editingAlert ? 'Edit Alert Rule' : 'Create Alert Rule'}
        triggerRef={editingAlert ? editButtonRefs.current[editingAlert.id] : createButtonRef}
      >
        <AlertForm
          alert={editingAlert}
          onSave={handleSaveAlert}
          onCancel={handleCloseModal}
          isLoading={createAlert.isPending || updateAlert.isPending}
        />
      </Modal>

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        isOpen={deleteConfirm.open}
        onClose={() => setDeleteConfirm({ open: false, alertId: null, alertName: '' })}
        onConfirm={confirmDelete}
        title="Delete Alert Rule"
        message={`Are you sure you want to delete "${deleteConfirm.alertName}"? This action cannot be undone.`}
        confirmText="Delete"
        cancelText="Cancel"
        variant="danger"
        triggerRef={deleteButtonRefs.current[deleteConfirm.alertId]}
      />
    </div>
  );
}

export default Alerts;
