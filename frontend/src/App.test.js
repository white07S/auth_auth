import { render, screen, waitForElementToBeRemoved } from '@testing-library/react';

import App from './App';

describe('App', () => {
  beforeEach(() => {
    global.fetch = jest.fn((url) => {
      if (url.includes('/auth/session')) {
        return Promise.resolve({
          ok: true,
          text: async () => JSON.stringify({
            is_authenticated: false,
            user: null,
            roles: [],
            expires_at: null,
          }),
        });
      }
      if (url.includes('/auth/login')) {
        return Promise.resolve({
          ok: true,
          text: async () => JSON.stringify({ authorization_url: 'https://example.com' }),
        });
      }
      if (url.includes('/auth/logout')) {
        return Promise.resolve({
          ok: true,
          text: async () => JSON.stringify({ success: true }),
        });
      }
      return Promise.resolve({ ok: true, text: async () => '{}' });
    });
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  test('renders login page by default', async () => {
    render(<App />);
    await waitForElementToBeRemoved(() => screen.queryByText(/Loading session/i));
    expect(await screen.findByText(/Sign in with Entra ID/i)).toBeInTheDocument();
  });
});
