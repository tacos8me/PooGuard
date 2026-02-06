import '@testing-library/jest-dom';
import { vi } from 'vitest';

// Mock the api module with proper interceptors
vi.mock('../lib/api', () => {
  const mockInterceptorId = 1;
  const requestInterceptors = [];
  const responseInterceptors = [];

  return {
    default: {
      get: vi.fn().mockResolvedValue({ data: {} }),
      post: vi.fn().mockResolvedValue({ data: {} }),
      put: vi.fn().mockResolvedValue({ data: {} }),
      delete: vi.fn().mockResolvedValue({ data: {} }),
      interceptors: {
        request: {
          use: vi.fn((success, error) => {
            requestInterceptors.push({ success, error });
            return mockInterceptorId;
          }),
          eject: vi.fn((id) => {
            // No-op in mock
          }),
        },
        response: {
          use: vi.fn((success, error) => {
            responseInterceptors.push({ success, error });
            return mockInterceptorId;
          }),
          eject: vi.fn((id) => {
            // No-op in mock
          }),
        },
      },
    },
    initializeCsrf: vi.fn().mockResolvedValue('mock-csrf-token'),
  };
});

// Mock localStorage
const localStorageMock = {
  getItem: vi.fn(),
  setItem: vi.fn(),
  removeItem: vi.fn(),
  clear: vi.fn(),
};
Object.defineProperty(window, 'localStorage', {
  value: localStorageMock,
});

// Mock socket.io-client
vi.mock('socket.io-client', () => ({
  default: vi.fn(() => ({
    on: vi.fn(),
    off: vi.fn(),
    emit: vi.fn(),
    connect: vi.fn(),
    disconnect: vi.fn(),
  })),
  io: vi.fn(() => ({
    on: vi.fn(),
    off: vi.fn(),
    emit: vi.fn(),
    connect: vi.fn(),
    disconnect: vi.fn(),
  })),
}));

// Reset mocks between tests
beforeEach(() => {
  vi.clearAllMocks();
  localStorageMock.getItem.mockReturnValue(null);
});
