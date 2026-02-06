import { useEffect, useRef } from 'react';
import useFocusTrap from '../hooks/useFocusTrap';

const VARIANT_CONFIG = {
  danger: {
    borderColor: 'border-l-red-500',
    iconColor: 'text-red-400',
    iconBg: 'bg-red-500/10',
    buttonStyle: 'bg-red-600 hover:bg-red-500 focus:ring-red-500',
    icon: (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={1.5}
          d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
        />
      </svg>
    ),
  },
  warning: {
    borderColor: 'border-l-amber-500',
    iconColor: 'text-amber-400',
    iconBg: 'bg-amber-500/10',
    buttonStyle: 'bg-amber-600 hover:bg-amber-500 focus:ring-amber-500',
    icon: (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={1.5}
          d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
        />
      </svg>
    ),
  },
  info: {
    borderColor: 'border-l-primary-500',
    iconColor: 'text-primary-400',
    iconBg: 'bg-primary-500/10',
    buttonStyle: 'bg-primary-600 hover:bg-primary-500 focus:ring-primary-500',
    icon: (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={1.5}
          d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
        />
      </svg>
    ),
  },
};

export default function ConfirmDialog({
  isOpen,
  onClose,
  onConfirm,
  title = 'Confirm Action',
  message = 'Are you sure you want to proceed?',
  confirmText = 'Confirm',
  cancelText = 'Cancel',
  variant = 'danger',
  triggerRef,
}) {
  const confirmButtonRef = useRef(null);

  const modalRef = useFocusTrap(isOpen, {
    onEscape: onClose,
    triggerRef,
  });

  useEffect(() => {
    if (isOpen && confirmButtonRef.current) {
      confirmButtonRef.current.focus();
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const styles = VARIANT_CONFIG[variant] || VARIANT_CONFIG.danger;

  function handleConfirm() {
    onConfirm();
    onClose();
  }

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      <div
        className="flex items-center justify-center min-h-screen px-4"
        onClick={(e) => e.target === e.currentTarget && onClose()}
      >
        {/* Overlay */}
        <div
          className="fixed inset-0 bg-black/60 backdrop-blur-sm animate-overlay-in"
          aria-hidden="true"
        />

        {/* Modal card */}
        <div
          ref={modalRef}
          className={`
            relative w-full max-w-md bg-zinc-900 border border-zinc-800
            border-l-2 ${styles.borderColor}
            rounded-lg shadow-xl animate-modal-in
          `}
          role="alertdialog"
          aria-modal="true"
          aria-labelledby="confirm-title"
          aria-describedby="confirm-description"
        >
          <div className="p-6">
            <div className="flex items-start gap-4">
              <div className={`p-2 rounded-lg ${styles.iconBg} ${styles.iconColor}`}>
                {styles.icon}
              </div>
              <div className="flex-1 min-w-0">
                <h3
                  id="confirm-title"
                  className="text-base font-bold text-zinc-100"
                >
                  {title}
                </h3>
                <p
                  id="confirm-description"
                  className="mt-1.5 text-sm text-zinc-400 leading-relaxed"
                >
                  {message}
                </p>
              </div>
            </div>

            <div className="mt-6 flex gap-3 justify-end">
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2 rounded-lg text-sm font-medium bg-zinc-800 hover:bg-zinc-700 text-zinc-300 transition-colors duration-150 focus:outline-none focus:ring-2 focus:ring-zinc-600 focus:ring-offset-2 focus:ring-offset-zinc-900"
              >
                {cancelText}
              </button>
              <button
                ref={confirmButtonRef}
                type="button"
                onClick={handleConfirm}
                className={`px-4 py-2 rounded-lg text-sm font-medium text-white transition-colors duration-150 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-zinc-900 ${styles.buttonStyle}`}
              >
                {confirmText}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
