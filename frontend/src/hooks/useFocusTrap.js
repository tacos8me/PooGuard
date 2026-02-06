import { useEffect, useRef, useCallback } from 'react';

/**
 * Custom hook for managing focus trapping within a modal or dialog.
 * Ensures keyboard users cannot tab outside of the modal content.
 *
 * @param {boolean} isActive - Whether the focus trap is currently active
 * @param {Object} options - Configuration options
 * @param {Function} options.onEscape - Callback to execute when Escape key is pressed
 * @param {React.RefObject} options.triggerRef - Reference to the element that triggered the modal
 * @returns {React.RefObject} - Ref to attach to the container element
 */
function useFocusTrap(isActive, options = {}) {
  const { onEscape, triggerRef } = options;
  const containerRef = useRef(null);
  const previousActiveElement = useRef(null);
  const wasActive = useRef(false);

  // Get all focusable elements within the container
  const getFocusableElements = useCallback(() => {
    if (!containerRef.current) return [];

    const focusableSelectors = [
      'button:not([disabled])',
      'a[href]',
      'input:not([disabled])',
      'select:not([disabled])',
      'textarea:not([disabled])',
      '[tabindex]:not([tabindex="-1"])',
    ].join(', ');

    return Array.from(containerRef.current.querySelectorAll(focusableSelectors));
  }, []);

  // Focus the first focusable element
  const focusFirstElement = useCallback(() => {
    const focusableElements = getFocusableElements();
    if (focusableElements.length > 0) {
      focusableElements[0].focus();
    }
  }, [getFocusableElements]);

  // Handle keydown events for focus trapping and escape key
  const handleKeyDown = useCallback((event) => {
    if (!isActive) return;

    // Handle Escape key
    if (event.key === 'Escape') {
      event.preventDefault();
      if (onEscape) {
        onEscape();
      }
      return;
    }

    // Handle Tab key for focus trapping
    if (event.key === 'Tab') {
      const focusableElements = getFocusableElements();
      if (focusableElements.length === 0) return;

      const firstElement = focusableElements[0];
      const lastElement = focusableElements[focusableElements.length - 1];

      if (event.shiftKey) {
        // Shift + Tab: going backwards
        if (document.activeElement === firstElement) {
          event.preventDefault();
          lastElement.focus();
        }
      } else {
        // Tab: going forwards
        if (document.activeElement === lastElement) {
          event.preventDefault();
          firstElement.focus();
        }
      }
    }
  }, [isActive, onEscape, getFocusableElements]);

  // Effect to manage focus when the trap is activated/deactivated
  useEffect(() => {
    if (isActive) {
      // Store the currently focused element to restore later
      previousActiveElement.current = document.activeElement;
      wasActive.current = true;

      // Focus the first element after a brief delay to ensure the modal is rendered
      const timeoutId = setTimeout(() => {
        focusFirstElement();
      }, 0);

      // Add keydown listener
      document.addEventListener('keydown', handleKeyDown);

      return () => {
        clearTimeout(timeoutId);
        document.removeEventListener('keydown', handleKeyDown);
      };
    } else if (wasActive.current) {
      // Only restore focus on a true→false transition, not on every re-render
      wasActive.current = false;
      const elementToFocus = triggerRef?.current || previousActiveElement.current;
      if (elementToFocus && typeof elementToFocus.focus === 'function') {
        elementToFocus.focus();
      }
      previousActiveElement.current = null;
    }
  }, [isActive, focusFirstElement, handleKeyDown, triggerRef]);

  return containerRef;
}

export default useFocusTrap;
