import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from '../lib/api';
import { useAuth } from '../context/AuthContext';
import ConfirmDialog from '../components/ConfirmDialog';

const THREAT_TYPES = [
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
// High Security catches partial detections; Balanced catches strong; Low Friction only high-confidence.
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

function getScoreBarColor(score) {
  if (score < 0.3) return 'bg-primary-500';
  if (score < 0.6) return 'bg-amber-500';
  return 'bg-red-500';
}

function getVerdictLabel(action) {
  switch (action) {
    case 'block': return 'Would Block';
    case 'flag': return 'Would Flag';
    default: return 'Would Allow';
  }
}

function getVerdictBadgeClasses(action) {
  switch (action) {
    case 'block': return 'bg-red-500/20 text-red-400 border border-red-500/30';
    case 'flag': return 'bg-amber-500/20 text-amber-400 border border-amber-500/30';
    default: return 'bg-primary-500/20 text-primary-400 border border-primary-500/30';
  }
}

// ActionButtonGroup component with keyboard navigation
function ActionButtonGroup({ threatKey, currentAction, onActionChange, getActionColor }) {
  const buttonRefs = useRef([]);

  // Handle keyboard navigation with arrow keys
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

    // Focus the new button
    if (buttonRefs.current[newIndex]) {
      buttonRefs.current[newIndex].focus();
    }
  }, [threatKey, onActionChange]);

  return (
    <div
      className="flex gap-3"
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
          className={`flex-1 py-3 px-4 rounded border-2 transition-all duration-200 font-mono text-xs uppercase tracking-widest focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 focus:ring-offset-dark-950 ${
            currentAction === action.value
              ? getActionColor(action.value)
              : 'text-dark-500 bg-dark-950 border-dark-700 hover:border-dark-600 hover:text-dark-400'
          }`}
        >
          <div className="flex items-center justify-center gap-2">
            {action.value === 'block' && (
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
              </svg>
            )}
            {action.value === 'flag' && (
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 21v-4m0 0V5a2 2 0 012-2h6.5l1 1H21l-3 6 3 6h-8.5l-1-1H5a2 2 0 00-2 2zm9-13.5V9" />
              </svg>
            )}
            {action.value === 'allow' && (
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
            )}
            {action.label}
          </div>
        </button>
      ))}
    </div>
  );
}

function Settings() {
  const queryClient = useQueryClient();
  const { user } = useAuth();

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

  const [modelConfig, setModelConfig] = useState({
    providerType: 'none',
    endpointUrl: '',
    apiKey: '',
    modelName: '',
  });
  const [apiKeyModified, setApiKeyModified] = useState(false);
  const [showApiKey, setShowApiKey] = useState(false);
  const [discoveredModels, setDiscoveredModels] = useState([]);
  const [connectionTest, setConnectionTest] = useState(null);

  const [safeguardModel, setSafeguardModel] = useState('20b');
  const [selectedPreset, setSelectedPreset] = useState('custom');

  const [dataRetentionDays, setDataRetentionDays] = useState(90);
  const [failMode, setFailMode] = useState('open');
  const [analysisMode, setAnalysisMode] = useState('sync');

  const [testText, setTestText] = useState('');
  const [testResult, setTestResult] = useState(null);
  const [hasChanges, setHasChanges] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [copied, setCopied] = useState(false);

  // API Keys state
  const [newKeyName, setNewKeyName] = useState('');
  const [newKeySecret, setNewKeySecret] = useState(null);
  const [keyCopied, setKeyCopied] = useState(false);
  const [keyToRevoke, setKeyToRevoke] = useState(null);

  const proxyEndpoint = useMemo(() => {
    const { protocol, hostname, port } = window.location;
    // In dev (Vite on 5173/3000), the backend is on 3001; in prod, /v1 is proxied on same origin
    const backendPort = port === '5173' || port === '3000' ? '3001' : port;
    return `${protocol}//${hostname}${backendPort ? ':' + backendPort : ''}/v1`;
  }, []);

  // Warn user about unsaved changes when navigating away
  useEffect(() => {
    const handleBeforeUnload = (e) => {
      if (hasChanges) {
        e.preventDefault();
        e.returnValue = '';
        return '';
      }
    };

    window.addEventListener('beforeunload', handleBeforeUnload);
    return () => window.removeEventListener('beforeunload', handleBeforeUnload);
  }, [hasChanges]);

  // Fetch current config
  const { data: config, isLoading, error } = useQuery({
    queryKey: ['firewallConfig'],
    queryFn: async () => {
      const response = await api.get('/api/firewall/config');
      return response.data;
    },
  });

  useEffect(() => {
    if (config) {
      setThresholds({
        prompt_injection: config.thresholds?.promptInjection ?? 0.70,
        jailbreak: config.thresholds?.jailbreak ?? 0.70,
        pii: config.thresholds?.pii ?? 0.70,
      });
      setActions({
        prompt_injection: config.actions?.promptInjection ?? 'block',
        jailbreak: config.actions?.jailbreak ?? 'block',
        pii: config.actions?.pii ?? 'flag',
      });
      if (config.modelConfig) {
        setModelConfig({
          providerType: config.modelConfig.providerType || 'none',
          endpointUrl: config.modelConfig.endpointUrl || '',
          apiKey: '',
          modelName: config.modelConfig.modelName || '',
        });
        setApiKeyModified(false);
      }
      setSafeguardModel(config.safeguardModel || '20b');
      setDataRetentionDays(config.dataRetentionDays ?? 90);
      setFailMode(config.failMode || 'open');
      setAnalysisMode(config.analysisMode || 'sync');
      // Detect if current thresholds match a known preset
      const loadedThresholds = {
        prompt_injection: config.thresholds?.promptInjection ?? 0.70,
        jailbreak: config.thresholds?.jailbreak ?? 0.70,
        pii: config.thresholds?.pii ?? 0.70,
      };
      const matchedPreset = Object.entries(THRESHOLD_PRESETS).find(([key, preset]) => {
        if (!preset.thresholds) return false;
        return Object.keys(preset.thresholds).every(
          (k) => Math.abs((preset.thresholds[k] || 0) - (loadedThresholds[k] || 0)) < 0.005
        );
      });
      setSelectedPreset(matchedPreset ? matchedPreset[0] : 'custom');
      setHasChanges(false);
    }
  }, [config]);

  const saveMutation = useMutation({
    mutationFn: async ({ thresholds, actions, modelConfig: mc, safeguardModel: sm, dataRetentionDays: drd, failMode: fm, analysisMode: am }) => {
      const payload = {
        thresholds: {
          promptInjection: thresholds.prompt_injection,
          jailbreak: thresholds.jailbreak,
          pii: thresholds.pii,
        },
        actions: {
          promptInjection: actions.prompt_injection,
          jailbreak: actions.jailbreak,
          pii: actions.pii,
        },
        modelConfig: {
          providerType: mc.providerType,
          endpointUrl: mc.endpointUrl,
          apiKey: apiKeyModified ? mc.apiKey : '__UNCHANGED__',
          modelName: mc.modelName,
        },
        safeguardModel: sm,
        dataRetentionDays: drd,
        failMode: fm,
        analysisMode: am,
      };
      const response = await api.put('/api/firewall/config', payload);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firewallConfig'] });
      setHasChanges(false);
      setApiKeyModified(false);
    },
  });

  const discoverMutation = useMutation({
    mutationFn: async () => {
      const response = await api.post('/api/firewall/model/discover', {
        endpointUrl: modelConfig.endpointUrl,
        apiKey: modelConfig.apiKey || undefined,
      });
      return response.data;
    },
    onSuccess: (data) => {
      setDiscoveredModels(data.models || []);
      setConnectionTest(null);
    },
  });

  const testConnectionMutation = useMutation({
    mutationFn: async () => {
      const response = await api.post('/api/firewall/model/test', {
        endpointUrl: modelConfig.endpointUrl,
        apiKey: modelConfig.apiKey || undefined,
        modelName: modelConfig.modelName || undefined,
      });
      return response.data;
    },
    onSuccess: (data) => setConnectionTest(data),
  });

  // API Keys query and mutations
  const { data: apiKeysData, isLoading: apiKeysLoading } = useQuery({
    queryKey: ['apiKeys'],
    queryFn: async () => {
      const response = await api.get('/api/apikeys');
      return response.data;
    },
  });

  const createKeyMutation = useMutation({
    mutationFn: async (name) => {
      const response = await api.post('/api/apikeys', { name });
      return response.data;
    },
    onSuccess: (data) => {
      setNewKeySecret(data.secret);
      setNewKeyName('');
      queryClient.invalidateQueries({ queryKey: ['apiKeys'] });
    },
  });

  const revokeKeyMutation = useMutation({
    mutationFn: async (keyId) => {
      const response = await api.delete(`/api/apikeys/${keyId}`);
      return response.data;
    },
    onSuccess: () => {
      setKeyToRevoke(null);
      queryClient.invalidateQueries({ queryKey: ['apiKeys'] });
    },
  });

  // Test analysis mutation
  const analyzeMutation = useMutation({
    mutationFn: async (text) => {
      const response = await api.post('/api/firewall/analyze?test=true', { text });
      return response.data;
    },
    onSuccess: (data) => {
      setTestResult(data);
    },
  });

  const handlePresetChange = (presetKey) => {
    setSelectedPreset(presetKey);
    const preset = THRESHOLD_PRESETS[presetKey];
    if (preset?.thresholds) {
      setThresholds({ ...preset.thresholds });
      setHasChanges(true);
    }
  };

  const handleThresholdChange = (key, value) => {
    setThresholds((prev) => ({ ...prev, [key]: value }));
    setSelectedPreset('custom');
    setHasChanges(true);
  };

  const handleActionChange = (key, value) => {
    setActions((prev) => ({ ...prev, [key]: value }));
    setHasChanges(true);
  };

  const handleSave = () => {
    saveMutation.mutate({ thresholds, actions, modelConfig, safeguardModel, dataRetentionDays, failMode, analysisMode });
  };

  const handleModelConfigChange = (field, value) => {
    setModelConfig(prev => ({ ...prev, [field]: value }));
    if (field === 'apiKey') setApiKeyModified(true);
    setHasChanges(true);
  };

  const handleAnalyze = () => {
    if (testText.trim()) {
      analyzeMutation.mutate(testText);
    }
  };

  const getActionColor = (action) => {
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
  };

  const wouldBeBlocked = (score, threatType) => {
    const threshold = thresholds[threatType] || 0.5;
    const action = actions[threatType] || 'allow';
    if (score >= threshold) {
      return action;
    }
    return 'allow';
  };

  if (user?.role !== 'admin') {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-bold text-dark-100 font-mono tracking-tight">Settings</h1>
        <div className="bg-dark-900 border border-dark-700 rounded p-8 text-center">
          <svg className="mx-auto h-12 w-12 text-red-500/60 mb-4" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z" />
          </svg>
          <p className="text-dark-300 text-lg font-medium font-mono">Admin Access Required</p>
          <p className="text-dark-500 text-sm mt-2">Only administrators can modify firewall configuration.</p>
        </div>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin h-8 w-8 border-4 border-primary-500 border-t-transparent rounded-full"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-4 rounded bg-red-500/10 border border-red-500/20 text-red-400 font-mono text-sm">
        Failed to load configuration: {error.message}
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-7xl">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-dark-100 font-mono tracking-tight">
            Firewall Settings
          </h1>
          <p className="text-dark-500 mt-1 text-sm">
            Configure threat detection thresholds, response actions, and model endpoints
          </p>
        </div>
        <button
          onClick={() => setShowConfirm(true)}
          disabled={!hasChanges || saveMutation.isPending}
          className={`flex items-center gap-2 px-5 py-2.5 rounded font-mono text-sm uppercase tracking-wider transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 focus:ring-offset-dark-950 ${
            hasChanges && !saveMutation.isPending
              ? 'bg-primary-600 hover:bg-primary-500 text-white shadow-glow-green-sm hover:shadow-glow-green'
              : 'bg-dark-700 text-dark-500 cursor-not-allowed'
          }`}
        >
          {saveMutation.isPending ? (
            <>
              <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                <circle
                  className="opacity-25"
                  cx="12"
                  cy="12"
                  r="10"
                  stroke="currentColor"
                  strokeWidth="4"
                  fill="none"
                />
                <path
                  className="opacity-75"
                  fill="currentColor"
                  d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                />
              </svg>
              Saving...
            </>
          ) : (
            <>
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
              Save Configuration
            </>
          )}
        </button>
      </div>

      {/* Status Messages */}
      {saveMutation.isSuccess && (
        <div className="p-3 rounded bg-primary-500/10 border border-primary-500/20 text-primary-400 font-mono text-sm flex items-center gap-2">
          <svg className="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
          </svg>
          Configuration saved successfully.
        </div>
      )}

      {saveMutation.isError && (
        <div className="p-3 rounded bg-red-500/10 border border-red-500/20 text-red-400 font-mono text-sm flex items-center gap-2">
          <svg className="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01" />
          </svg>
          Failed to save configuration: {saveMutation.error?.message}
        </div>
      )}

      {/* Two-column grid on wide screens */}
      <div className="grid lg:grid-cols-2 gap-6">

        {/* LEFT COLUMN — Threat Detection Rules */}
        <div className="space-y-6">
          {/* Combined Threshold + Action per threat type */}
          {/* Threshold Presets */}
          <div className="space-y-0">
            <div className="px-1 mb-3">
              <h2 className="text-xs font-mono uppercase tracking-widest text-dark-400 mb-1">
                Threshold Preset
              </h2>
              <p className="text-dark-500 text-xs">
                Choose a preset profile or configure thresholds manually below.
              </p>
            </div>
            <div className="grid grid-cols-2 gap-2">
              {Object.entries(THRESHOLD_PRESETS).map(([key, preset]) => (
                <button
                  key={key}
                  onClick={() => handlePresetChange(key)}
                  className={`p-3 rounded border-2 transition-all duration-200 text-left focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 focus:ring-offset-dark-950 ${
                    selectedPreset === key
                      ? 'border-primary-500/40 bg-primary-500/5'
                      : 'border-dark-700 bg-dark-950 hover:border-dark-600'
                  }`}
                >
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`${selectedPreset === key ? 'text-primary-400' : 'text-dark-400'}`}>
                      {preset.icon}
                    </span>
                    <span className={`font-mono text-xs font-bold uppercase tracking-wider ${
                      selectedPreset === key ? 'text-primary-400' : 'text-dark-300'
                    }`}>
                      {preset.label}
                    </span>
                  </div>
                  <p className={`text-[10px] font-mono leading-relaxed ${
                    selectedPreset === key ? 'text-dark-400' : 'text-dark-500'
                  }`}>
                    {preset.description}
                  </p>
                </button>
              ))}
            </div>
          </div>

          <div className="space-y-0">
            <div className="px-1 mb-3">
              <h2 className="text-xs font-mono uppercase tracking-widest text-dark-400 mb-1">
                Detection Rules
              </h2>
              <p className="text-dark-500 text-xs">
                Threshold sensitivity and response action per threat type.
                {selectedPreset !== 'custom' && (
                  <span className="ml-1 text-primary-400">
                    Using {THRESHOLD_PRESETS[selectedPreset]?.label} preset. Adjust sliders to customize.
                  </span>
                )}
              </p>
            </div>
            <div className="space-y-3">
              {THREAT_TYPES.map((threat) => {
                const value = Number(thresholds[threat.key] ?? threat.defaultThreshold);
                return (
                  <div
                    key={threat.key}
                    className={`bg-dark-900 border border-dark-700 border-l-4 ${BORDER_COLORS[threat.key]} rounded p-5 space-y-4`}
                  >
                    {/* Threshold section */}
                    <div>
                      <div className="flex items-center justify-between mb-3">
                        <label className="text-xs font-mono uppercase tracking-widest text-dark-400">
                          {threat.label}
                        </label>
                        <span className="text-xl font-mono text-dark-100 tabular-nums">
                          {value.toFixed(2)}
                        </span>
                      </div>
                      <div className="flex items-center gap-3">
                        <span className="text-[10px] font-mono text-dark-600 w-6 text-right">0.0</span>
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
                        <span className="text-[10px] font-mono text-dark-600 w-6">1.0</span>
                      </div>
                      <p className="text-[11px] text-dark-500 mt-1.5 font-mono">
                        {getSensitivityLabel(value)}
                      </p>
                    </div>

                    {/* Action section */}
                    <div className="pt-3 border-t border-dark-800">
                      <label
                        id={`action-label-${threat.key}`}
                        className="text-[10px] font-mono uppercase tracking-widest text-dark-500 block mb-2"
                      >
                        Response Action
                      </label>
                      <ActionButtonGroup
                        threatKey={threat.key}
                        currentAction={actions[threat.key]}
                        onActionChange={handleActionChange}
                        getActionColor={getActionColor}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* RIGHT COLUMN — Model Configuration + Test */}
        <div className="space-y-6">

          {/* Proxy Endpoint */}
          <div className="bg-dark-900 border border-dark-700 rounded p-4 flex items-center justify-between gap-4">
            <div className="min-w-0">
              <p className="text-[10px] font-mono uppercase tracking-widest text-dark-500 mb-1">
                Proxy Endpoint
              </p>
              <code className="text-sm font-mono text-dark-200 break-all">{proxyEndpoint}</code>
            </div>
            <button
              onClick={() => {
                navigator.clipboard.writeText(proxyEndpoint);
                setCopied(true);
                setTimeout(() => setCopied(false), 2000);
              }}
              className="shrink-0 p-2 rounded border border-dark-700 bg-dark-950 text-dark-400 hover:text-dark-200 hover:border-dark-500 transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 focus:ring-offset-dark-950"
              aria-label="Copy proxy endpoint"
              title="Copy to clipboard"
            >
              {copied ? (
                <svg className="w-4 h-4 text-primary-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
              ) : (
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                </svg>
              )}
            </button>
          </div>

          {/* Proxy API Keys */}
          <div className="space-y-0">
            <div className="px-1 mb-3">
              <h2 className="text-xs font-mono uppercase tracking-widest text-dark-400 mb-1">
                Proxy API Keys
              </h2>
              <p className="text-dark-500 text-xs">
                Generate API keys for external OAI-compatible clients to authenticate with the proxy.
              </p>
            </div>
            <div className="bg-dark-900 border border-dark-700 rounded p-5 space-y-4">
              {/* One-time secret display */}
              {newKeySecret && (
                <div className="p-3 rounded bg-primary-500/10 border border-primary-500/30">
                  <p className="text-xs font-mono text-primary-400 mb-2">
                    Copy this key now — it won&apos;t be shown again:
                  </p>
                  <div className="flex items-center gap-2">
                    <code className="flex-1 text-sm font-mono text-dark-100 break-all select-all bg-dark-950 px-3 py-2 rounded">
                      {newKeySecret}
                    </code>
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(newKeySecret);
                        setKeyCopied(true);
                        setTimeout(() => setKeyCopied(false), 2000);
                      }}
                      className="shrink-0 p-2 rounded border border-dark-700 bg-dark-950 text-dark-400 hover:text-dark-200 hover:border-dark-500 transition-all duration-200"
                      aria-label="Copy API key"
                    >
                      {keyCopied ? (
                        <svg className="w-4 h-4 text-primary-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                        </svg>
                      ) : (
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                        </svg>
                      )}
                    </button>
                  </div>
                  <button
                    onClick={() => setNewKeySecret(null)}
                    className="mt-2 text-xs text-dark-500 hover:text-dark-300 font-mono"
                  >
                    Dismiss
                  </button>
                </div>
              )}

              {/* Create key form */}
              <div className="flex gap-2">
                <input
                  type="text"
                  value={newKeyName}
                  onChange={(e) => setNewKeyName(e.target.value)}
                  placeholder="Key name (e.g. SillyTavern)"
                  className="flex-1 px-4 py-2.5 bg-dark-950 border border-dark-700 rounded text-dark-100 font-mono text-sm placeholder-dark-600 focus:outline-none focus:ring-1 focus:ring-primary-500 focus:border-primary-500 transition-all duration-200"
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && newKeyName.trim()) {
                      createKeyMutation.mutate(newKeyName.trim());
                    }
                  }}
                />
                <button
                  onClick={() => createKeyMutation.mutate(newKeyName.trim())}
                  disabled={!newKeyName.trim() || createKeyMutation.isPending}
                  className="px-4 py-2.5 rounded bg-primary-600 hover:bg-primary-500 text-white font-mono text-xs uppercase tracking-wider transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 focus:ring-offset-dark-950 disabled:opacity-40 disabled:cursor-not-allowed whitespace-nowrap"
                >
                  {createKeyMutation.isPending ? 'Creating...' : 'Create Key'}
                </button>
              </div>
              {createKeyMutation.isError && (
                <p className="text-red-400 text-xs font-mono">
                  {createKeyMutation.error?.response?.data?.error || createKeyMutation.error?.message}
                </p>
              )}

              {/* Key list */}
              {apiKeysLoading ? (
                <p className="text-dark-500 text-xs font-mono">Loading keys...</p>
              ) : apiKeysData?.keys?.length > 0 ? (
                <div className="space-y-2">
                  {apiKeysData.keys.map((k) => (
                    <div key={k.id} className="flex items-center justify-between gap-3 p-3 rounded bg-dark-950 border border-dark-700">
                      <div className="min-w-0 flex-1">
                        <p className="text-sm font-mono text-dark-200 truncate">{k.name}</p>
                        <div className="flex items-center gap-3 mt-0.5">
                          <code className="text-xs font-mono text-dark-500">{k.prefix}...</code>
                          {k.lastUsedAt && (
                            <span className="text-xs text-dark-600">
                              Last used {new Date(k.lastUsedAt).toLocaleDateString()}
                            </span>
                          )}
                          <span className="text-xs text-dark-600">
                            Created {new Date(k.createdAt).toLocaleDateString()}
                          </span>
                        </div>
                      </div>
                      <button
                        onClick={() => setKeyToRevoke(k)}
                        disabled={revokeKeyMutation.isPending}
                        className="shrink-0 px-3 py-1.5 rounded border border-red-500/30 text-red-400 hover:bg-red-500/10 hover:border-red-500/50 font-mono text-xs uppercase tracking-wider transition-all duration-200 disabled:opacity-40"
                      >
                        Revoke
                      </button>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-dark-600 text-xs font-mono">
                  No API keys yet. Create one to connect external clients.
                </p>
              )}
            </div>
          </div>

          {/* Revoke key confirmation */}
          <ConfirmDialog
            isOpen={!!keyToRevoke}
            onClose={() => setKeyToRevoke(null)}
            onConfirm={() => keyToRevoke && revokeKeyMutation.mutate(keyToRevoke.id)}
            title="Revoke API Key"
            message={`Revoke "${keyToRevoke?.name}"? Any client using this key will immediately lose access.`}
            confirmText="Revoke"
            variant="danger"
          />

          {/* Upstream Model */}
          <div className="space-y-0">
            <div className="px-1 mb-3">
              <h2 className="text-xs font-mono uppercase tracking-widest text-dark-400 mb-1">
                Upstream Model
              </h2>
              <p className="text-dark-500 text-xs">
                Configure the LLM endpoint PooGuard proxies to. Supports any OAI-compatible API.
              </p>
            </div>
            <div className="bg-dark-900 border border-dark-700 rounded p-5 space-y-4">
              {/* Provider toggle */}
              <div className="flex gap-3" role="radiogroup" aria-label="Provider type">
                {[
                  { value: 'none', label: 'Analysis Only' },
                  { value: 'openai_compatible', label: 'OAI-Compatible Endpoint' },
                ].map((opt) => (
                  <button
                    key={opt.value}
                    role="radio"
                    aria-checked={modelConfig.providerType === opt.value}
                    tabIndex={modelConfig.providerType === opt.value ? 0 : -1}
                    onClick={() => handleModelConfigChange('providerType', opt.value)}
                    className={`flex-1 py-2.5 px-3 rounded border-2 transition-all duration-200 font-mono text-xs uppercase tracking-widest focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 focus:ring-offset-dark-950 ${
                      modelConfig.providerType === opt.value
                        ? 'text-primary-400 bg-primary-500/10 border-primary-500/40'
                        : 'text-dark-500 bg-dark-950 border-dark-700 hover:border-dark-600 hover:text-dark-400'
                    }`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>

              {modelConfig.providerType === 'none' ? (
                <div className="p-4 rounded bg-dark-950 border border-dark-700">
                  <p className="text-dark-500 text-xs font-mono">
                    Running in analysis-only mode. The firewall will score and block/flag requests but won&apos;t proxy to an LLM.
                    Toggle to &quot;OAI-Compatible Endpoint&quot; to configure upstream proxying.
                  </p>
                </div>
              ) : (
                <>
                  {/* Endpoint URL */}
                  <div>
                    <label className="block text-xs font-mono uppercase tracking-widest text-dark-400 mb-1.5">
                      Endpoint URL
                    </label>
                    <input
                      type="text"
                      value={modelConfig.endpointUrl}
                      onChange={(e) => handleModelConfigChange('endpointUrl', e.target.value)}
                      placeholder="https://api.openai.com/v1"
                      className="w-full px-4 py-2.5 bg-dark-950 border border-dark-700 rounded text-dark-100 font-mono text-sm placeholder-dark-600 focus:outline-none focus:ring-1 focus:ring-primary-500 focus:border-primary-500 transition-all duration-200"
                    />
                    <p className="text-dark-600 text-xs font-mono mt-1">
                      Include /v1 in the path. For local LLMs (Ollama, vLLM), use host.docker.internal instead of localhost.
                    </p>
                  </div>

                  {/* API Key */}
                  <div>
                    <label className="block text-xs font-mono uppercase tracking-widest text-dark-400 mb-1.5">
                      API Key
                      {config?.modelConfig?.hasApiKey && !apiKeyModified && (
                        <span className="ml-2 text-primary-500 normal-case tracking-normal">
                          (configured)
                        </span>
                      )}
                    </label>
                    <div className="relative">
                      <input
                        type={showApiKey ? 'text' : 'password'}
                        value={modelConfig.apiKey}
                        onChange={(e) => handleModelConfigChange('apiKey', e.target.value)}
                        placeholder={config?.modelConfig?.hasApiKey ? 'Leave empty to keep current key' : 'sk-... (optional)'}
                        className="w-full px-4 py-2.5 pr-10 bg-dark-950 border border-dark-700 rounded text-dark-100 font-mono text-sm placeholder-dark-600 focus:outline-none focus:ring-1 focus:ring-primary-500 focus:border-primary-500 transition-all duration-200"
                        autoComplete="off"
                      />
                      <button
                        type="button"
                        onClick={() => setShowApiKey(!showApiKey)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-dark-500 hover:text-dark-300 transition-colors"
                        aria-label={showApiKey ? 'Hide API key' : 'Show API key'}
                      >
                        {showApiKey ? (
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
                          </svg>
                        ) : (
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                          </svg>
                        )}
                      </button>
                    </div>
                  </div>

                  {/* Model Name + Discovery */}
                  <div>
                    <label className="block text-xs font-mono uppercase tracking-widest text-dark-400 mb-1.5">
                      Model
                    </label>
                    <div className="flex gap-2">
                      {discoveredModels.length > 0 ? (
                        <select
                          value={modelConfig.modelName}
                          onChange={(e) => handleModelConfigChange('modelName', e.target.value)}
                          className="flex-1 px-4 py-2.5 bg-dark-950 border border-dark-700 rounded text-dark-100 font-mono text-sm focus:outline-none focus:ring-1 focus:ring-primary-500 focus:border-primary-500 transition-all duration-200"
                        >
                          <option value="">Select a model...</option>
                          {discoveredModels.map((m) => (
                            <option key={m} value={m}>{m}</option>
                          ))}
                        </select>
                      ) : (
                        <input
                          type="text"
                          value={modelConfig.modelName}
                          onChange={(e) => handleModelConfigChange('modelName', e.target.value)}
                          placeholder="llama3:8b or gpt-4o"
                          className="flex-1 px-4 py-2.5 bg-dark-950 border border-dark-700 rounded text-dark-100 font-mono text-sm placeholder-dark-600 focus:outline-none focus:ring-1 focus:ring-primary-500 focus:border-primary-500 transition-all duration-200"
                        />
                      )}
                      <button
                        onClick={() => discoverMutation.mutate()}
                        disabled={!modelConfig.endpointUrl || discoverMutation.isPending}
                        className="px-4 py-2.5 rounded bg-dark-800 border border-dark-600 text-dark-300 hover:text-dark-100 hover:border-dark-500 font-mono text-xs uppercase tracking-wider transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 focus:ring-offset-dark-950 disabled:opacity-40 disabled:cursor-not-allowed whitespace-nowrap"
                      >
                        {discoverMutation.isPending ? (
                          <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                          </svg>
                        ) : 'Discover'}
                      </button>
                    </div>
                    {discoverMutation.isError && (
                      <p className="text-red-400 text-xs font-mono mt-1.5">
                        Discovery failed: {discoverMutation.error?.response?.data?.error || discoverMutation.error?.message}
                      </p>
                    )}
                    {discoveredModels.length > 0 && (
                      <p className="text-dark-500 text-xs font-mono mt-1.5">
                        Found {discoveredModels.length} model{discoveredModels.length !== 1 ? 's' : ''}
                        <button
                          onClick={() => setDiscoveredModels([])}
                          className="ml-2 text-dark-400 hover:text-dark-300 underline"
                        >
                          clear
                        </button>
                      </p>
                    )}
                  </div>

                  {/* Test Connection */}
                  <div className="flex items-center gap-3 pt-1">
                    <button
                      onClick={() => testConnectionMutation.mutate()}
                      disabled={!modelConfig.endpointUrl || testConnectionMutation.isPending}
                      className="flex items-center gap-2 px-4 py-2.5 rounded bg-dark-800 border border-dark-600 text-dark-300 hover:text-dark-100 hover:border-dark-500 font-mono text-xs uppercase tracking-wider transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 focus:ring-offset-dark-950 disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                      {testConnectionMutation.isPending ? (
                        <>
                          <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                          </svg>
                          Testing...
                        </>
                      ) : (
                        <>
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                          </svg>
                          Test Connection
                        </>
                      )}
                    </button>

                    {connectionTest && (
                      <span className={`text-xs font-mono ${connectionTest.success ? 'text-primary-400' : 'text-red-400'}`}>
                        {connectionTest.success ? (
                          <>
                            <svg className="w-3.5 h-3.5 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                            </svg>
                            Connected ({connectionTest.latencyMs}ms)
                          </>
                        ) : (
                          <>
                            <svg className="w-3.5 h-3.5 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                            </svg>
                            {connectionTest.error}
                          </>
                        )}
                      </span>
                    )}
                  </div>
                </>
              )}
            </div>
          </div>

          {/* Safeguard Model */}
          <div className="space-y-0">
            <div className="px-1 mb-3">
              <h2 className="text-xs font-mono uppercase tracking-widest text-dark-400 mb-1">
                Safeguard Model
              </h2>
              <p className="text-dark-500 text-xs">
                Choose which OSS-safeguard model the threat classifier uses.
              </p>
            </div>
            <div className="bg-dark-900 border border-dark-700 rounded p-5">
              <div className="flex gap-3" role="radiogroup" aria-label="Safeguard model variant">
                {[
                  {
                    value: '20b',
                    label: '20B',
                    desc: 'Faster inference, lower resource usage. Good for development and moderate workloads.',
                  },
                  {
                    value: '120b',
                    label: '120B',
                    desc: 'Higher accuracy, more resource intensive. Recommended for production.',
                  },
                ].map((opt) => (
                  <button
                    key={opt.value}
                    role="radio"
                    aria-checked={safeguardModel === opt.value}
                    tabIndex={safeguardModel === opt.value ? 0 : -1}
                    onClick={() => { setSafeguardModel(opt.value); setHasChanges(true); }}
                    className={`flex-1 p-4 rounded border-2 transition-all duration-200 text-left focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 focus:ring-offset-dark-950 ${
                      safeguardModel === opt.value
                        ? 'border-primary-500/40 bg-primary-500/5'
                        : 'border-dark-700 bg-dark-950 hover:border-dark-600'
                    }`}
                  >
                    <div className="flex items-center gap-2 mb-1.5">
                      <span className={`font-mono text-sm font-bold ${
                        safeguardModel === opt.value ? 'text-primary-400' : 'text-dark-300'
                      }`}>
                        {opt.label}
                      </span>
                      {opt.value === '120b' && (
                        <span className="text-[9px] font-mono uppercase tracking-widest px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">
                          GPU
                        </span>
                      )}
                    </div>
                    <p className={`text-xs font-mono ${
                      safeguardModel === opt.value ? 'text-dark-400' : 'text-dark-500'
                    }`}>
                      {opt.desc}
                    </p>
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Analysis Mode */}
          <div className="space-y-0">
            <div className="px-1 mb-3">
              <h2 className="text-xs font-mono uppercase tracking-widest text-dark-400 mb-1">
                Analysis Mode
              </h2>
              <p className="text-dark-500 text-xs">
                Control whether threat analysis blocks requests or runs in the background.
              </p>
            </div>
            <div className="bg-dark-900 border border-dark-700 rounded p-5">
              <div className="flex gap-3" role="radiogroup" aria-label="Analysis mode">
                {[
                  {
                    value: 'sync',
                    label: 'Synchronous',
                    desc: 'Analyze before responding. Blocks threats in real-time.',
                  },
                  {
                    value: 'async',
                    label: 'Asynchronous',
                    desc: 'Respond immediately, analyze in background. Zero added latency.',
                  },
                ].map((opt) => (
                  <button
                    key={opt.value}
                    role="radio"
                    aria-checked={analysisMode === opt.value}
                    tabIndex={analysisMode === opt.value ? 0 : -1}
                    onClick={() => { setAnalysisMode(opt.value); setHasChanges(true); }}
                    className={`flex-1 p-4 rounded border-2 transition-all duration-200 text-left focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 focus:ring-offset-dark-950 ${
                      analysisMode === opt.value
                        ? 'border-primary-500/40 bg-primary-500/5'
                        : 'border-dark-700 bg-dark-950 hover:border-dark-600'
                    }`}
                  >
                    <div className="flex items-center gap-2 mb-1.5">
                      <span className={`font-mono text-sm font-bold ${
                        analysisMode === opt.value ? 'text-primary-400' : 'text-dark-300'
                      }`}>
                        {opt.label}
                      </span>
                      {opt.value === 'async' && (
                        <span className="text-[9px] font-mono uppercase tracking-widest px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">
                          Beta
                        </span>
                      )}
                    </div>
                    <p className={`text-xs font-mono ${
                      analysisMode === opt.value ? 'text-dark-400' : 'text-dark-500'
                    }`}>
                      {opt.desc}
                    </p>
                  </button>
                ))}
              </div>
              {analysisMode === 'async' && (
                <p className="text-amber-400/80 text-xs font-mono mt-3 p-2 rounded bg-amber-500/5 border border-amber-500/10">
                  Async mode does not block threats in real-time. Threats are detected and logged retroactively. Use for low-risk workloads where latency is critical.
                </p>
              )}
            </div>
          </div>

          {/* Compliance & Safety */}
          <div className="space-y-0">
            <div className="px-1 mb-3">
              <h2 className="text-xs font-mono uppercase tracking-widest text-dark-400 mb-1">
                Compliance &amp; Safety
              </h2>
              <p className="text-dark-500 text-xs">
                Data retention, fail mode, and GDPR controls.
              </p>
            </div>
            <div className="bg-dark-900 border border-dark-700 rounded p-5 space-y-5">
              {/* Data Retention */}
              <div>
                <label className="block text-xs font-mono uppercase tracking-widest text-dark-400 mb-1.5">
                  Data Retention (days)
                </label>
                <div className="flex items-center gap-3">
                  <input
                    type="number"
                    min="0"
                    max="3650"
                    value={dataRetentionDays}
                    onChange={(e) => {
                      setDataRetentionDays(parseInt(e.target.value, 10) || 0);
                      setHasChanges(true);
                    }}
                    className="w-28 px-4 py-2.5 bg-dark-950 border border-dark-700 rounded text-dark-100 font-mono text-sm focus:outline-none focus:ring-1 focus:ring-primary-500 focus:border-primary-500 transition-all duration-200"
                  />
                  <span className="text-xs text-dark-500 font-mono">
                    {dataRetentionDays === 0
                      ? 'Keep forever (no auto-cleanup)'
                      : `Request and egress logs older than ${dataRetentionDays} days are deleted`}
                  </span>
                </div>
                <p className="text-[11px] text-dark-600 font-mono mt-1.5">
                  Audit logs are always kept for compliance.
                </p>
              </div>

              {/* Fail Mode */}
              <div className="pt-3 border-t border-dark-800">
                <label className="block text-xs font-mono uppercase tracking-widest text-dark-400 mb-2">
                  Fail Mode
                </label>
                <div className="flex gap-3" role="radiogroup" aria-label="Fail mode">
                  {[
                    { value: 'open', label: 'Fail Open', desc: 'Return error when model is down (current requests pass through)' },
                    { value: 'closed', label: 'Fail Closed', desc: 'Block all requests when model is unavailable' },
                  ].map((opt) => (
                    <button
                      key={opt.value}
                      role="radio"
                      aria-checked={failMode === opt.value}
                      tabIndex={failMode === opt.value ? 0 : -1}
                      onClick={() => { setFailMode(opt.value); setHasChanges(true); }}
                      className={`flex-1 p-4 rounded border-2 transition-all duration-200 text-left focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 focus:ring-offset-dark-950 ${
                        failMode === opt.value
                          ? opt.value === 'closed'
                            ? 'border-red-500/40 bg-red-500/5'
                            : 'border-primary-500/40 bg-primary-500/5'
                          : 'border-dark-700 bg-dark-950 hover:border-dark-600'
                      }`}
                    >
                      <span className={`font-mono text-sm font-bold block mb-1 ${
                        failMode === opt.value
                          ? opt.value === 'closed' ? 'text-red-400' : 'text-primary-400'
                          : 'text-dark-300'
                      }`}>
                        {opt.label}
                      </span>
                      <p className={`text-xs font-mono ${
                        failMode === opt.value ? 'text-dark-400' : 'text-dark-500'
                      }`}>
                        {opt.desc}
                      </p>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Test Analysis */}
          <div className="space-y-0">
            <div className="px-1 mb-3">
              <h2 className="text-xs font-mono uppercase tracking-widest text-dark-400 mb-1">
                Test Analysis
              </h2>
              <p className="text-dark-500 text-xs">
                Dry-run text against the firewall. Not logged or processed.
              </p>
            </div>
            <div className="bg-dark-900 border border-dark-700 rounded p-5 space-y-4">
              <textarea
                value={testText}
                onChange={(e) => setTestText(e.target.value)}
                placeholder="Enter text to analyze..."
                className="w-full min-h-[100px] resize-y bg-dark-950 border border-dark-700 rounded p-4 text-dark-100 font-mono text-sm placeholder-dark-600 focus:outline-none focus:ring-1 focus:ring-primary-500 focus:border-primary-500 transition-all duration-200"
              />
              <button
                onClick={handleAnalyze}
                disabled={!testText.trim() || analyzeMutation.isPending}
                className="flex items-center gap-2 px-4 py-2.5 rounded bg-dark-800 border border-dark-600 text-dark-300 hover:text-dark-100 hover:border-dark-500 font-mono text-xs uppercase tracking-wider transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 focus:ring-offset-dark-950 disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:border-dark-600 disabled:hover:text-dark-300"
              >
                {analyzeMutation.isPending ? (
                  <>
                    <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                    </svg>
                    Analyzing...
                  </>
                ) : (
                  <>
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
                    </svg>
                    Analyze
                  </>
                )}
              </button>

              {analyzeMutation.isError && (
                <div className="p-3 rounded bg-red-500/10 border border-red-500/20 text-red-400 font-mono text-sm">
                  Analysis failed: {analyzeMutation.error?.message}
                </div>
              )}

              {testResult && (
                <div className="mt-2 bg-dark-950 border border-dark-700 rounded overflow-hidden">
                  {/* Terminal-style header */}
                  <div className="flex items-center gap-2 px-4 py-2 border-b border-dark-800 bg-dark-950">
                    <div className="flex gap-1.5">
                      <div className="w-2.5 h-2.5 rounded-full bg-red-500/60"></div>
                      <div className="w-2.5 h-2.5 rounded-full bg-amber-500/60"></div>
                      <div className="w-2.5 h-2.5 rounded-full bg-primary-500/60"></div>
                    </div>
                    <span className="text-[10px] font-mono text-dark-600 uppercase tracking-widest ml-2">
                      Analysis Output
                    </span>
                  </div>

                  <div className="p-4 space-y-3">
                    {THREAT_TYPES.map((threat) => {
                      const score = testResult.threatScores?.[threat.key] ?? 0;
                      const resultAction = wouldBeBlocked(score, threat.key);
                      const threshold = Number(thresholds[threat.key] || threat.defaultThreshold);
                      const isAboveThreshold = score >= threshold;

                      return (
                        <div key={threat.key} className="space-y-1">
                          <div className="flex items-center justify-between">
                            <span className="text-xs font-mono uppercase tracking-wider text-dark-400">
                              {threat.label}
                            </span>
                            <div className="flex items-center gap-3">
                              <span className={`text-sm font-mono tabular-nums ${isAboveThreshold ? 'text-red-400' : 'text-dark-300'}`}>
                                {(score * 100).toFixed(1)}%
                              </span>
                              <span className={`text-[10px] font-mono uppercase tracking-widest px-2 py-0.5 rounded ${getVerdictBadgeClasses(resultAction)}`}>
                                {getVerdictLabel(resultAction)}
                              </span>
                            </div>
                          </div>
                          <div className="relative w-full h-1.5 bg-dark-800 rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full transition-all duration-500 ${getScoreBarColor(score)}`}
                              style={{ width: `${score * 100}%` }}
                            />
                            <div
                              className="absolute top-0 h-full w-px bg-dark-400/50"
                              style={{ left: `${threshold * 100}%` }}
                              title={`Threshold: ${threshold.toFixed(2)}`}
                            />
                          </div>
                        </div>
                      );
                    })}

                    {/* Overall verdict */}
                    <div className="pt-3 border-t border-dark-800">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-mono uppercase tracking-widest text-dark-500">
                          Verdict
                        </span>
                        {(() => {
                          const hasBlock = THREAT_TYPES.some((t) => {
                            const score = testResult.threatScores?.[t.key] ?? 0;
                            return wouldBeBlocked(score, t.key) === 'block';
                          });
                          const hasFlag = THREAT_TYPES.some((t) => {
                            const score = testResult.threatScores?.[t.key] ?? 0;
                            return wouldBeBlocked(score, t.key) === 'flag';
                          });

                          if (hasBlock) {
                            return (
                              <span className="flex items-center gap-2 text-red-400 font-mono text-sm">
                                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
                                </svg>
                                BLOCKED
                              </span>
                            );
                          }
                          if (hasFlag) {
                            return (
                              <span className="flex items-center gap-2 text-amber-400 font-mono text-sm">
                                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                                </svg>
                                FLAGGED
                              </span>
                            );
                          }
                          return (
                            <span className="flex items-center gap-2 text-primary-400 font-mono text-sm">
                              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                              </svg>
                              ALLOWED
                            </span>
                          );
                        })()}
                      </div>
                    </div>

                    <p className="text-[10px] text-dark-600 font-mono pt-1">
                      // dry-run only -- not logged or processed by the firewall
                    </p>
                  </div>
                </div>
              )}
            </div>
          </div>

        </div>{/* end right column */}
      </div>{/* end grid */}

      <ConfirmDialog
        isOpen={showConfirm}
        onClose={() => setShowConfirm(false)}
        onConfirm={() => {
          setShowConfirm(false);
          handleSave();
        }}
        title="Save Configuration"
        message="This will update firewall rules for all incoming requests. Changes take effect immediately."
        variant="warning"
        confirmText="Save Changes"
      />
    </div>
  );
}

export default Settings;
