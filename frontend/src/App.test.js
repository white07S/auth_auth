import { render, screen } from "@testing-library/react";
import App from "./App";

beforeEach(() => {
  global.fetch = jest.fn(() =>
    Promise.resolve({
      ok: false,
      status: 401,
      text: () => Promise.resolve('{"detail":"Not authenticated"}'),
    }),
  );
});

afterEach(() => {
  jest.resetAllMocks();
});

test("renders login prompt", async () => {
  render(<App />);
  const button = await screen.findByRole("button", { name: /sign in with microsoft/i });
  expect(button).toBeInTheDocument();
});
