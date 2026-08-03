import type { APIRequestContext, Page } from '@playwright/test';

const BASE_URL = process.env.BASE_URL || 'http://localhost:8089';

/**
 * Direct API helpers for test setup/teardown.
 * Bypasses the browser UI to create/delete resources.
 */
export class PerseaApi {
  constructor(
    private request: APIRequestContext,
    private apiKey?: string,
  ) {}

  private headers(extra?: Record<string, string>): Record<string, string> {
    const h: Record<string, string> = { ...extra };
    if (this.apiKey) h['Authorization'] = `Bearer ${this.apiKey}`;
    return h;
  }

  // ── Sessions ──

  async listSessions(): Promise<Session[]> {
    const res = await this.request.get(`${BASE_URL}/api/sessions?all=true`, {
      headers: this.headers(),
    });
    return res.json();
  }

  async createSession(body: Record<string, unknown>): Promise<Session> {
    const res = await this.request.post(`${BASE_URL}/api/sessions`, {
      headers: this.headers({ 'Content-Type': 'application/json' }),
      data: body,
    });
    return res.json();
  }

  async deleteSession(sessionId: string): Promise<void> {
    await this.request.delete(`${BASE_URL}/api/sessions/${sessionId}`, {
      headers: this.headers(),
    });
  }

  // ── System Status ──

  async getSystemStatus(): Promise<SystemStatus> {
    const res = await this.request.get(`${BASE_URL}/api/system/status`, {
      headers: this.headers(),
    });
    return res.json();
  }

  // ── Users ──

  async listUsers(): Promise<User[]> {
    const res = await this.request.get(`${BASE_URL}/api/users`, {
      headers: this.headers(),
    });
    return res.json();
  }

  // ── Recordings ──

  async listRecordings(): Promise<Recording[]> {
    const res = await this.request.get(`${BASE_URL}/api/recordings`, {
      headers: this.headers(),
    });
    return res.json();
  }

  // ── Me ──

  async getMe(): Promise<Me> {
    const res = await this.request.get(`${BASE_URL}/api/me`, {
      headers: this.headers(),
    });
    return res.json();
  }

  // ── Auth status ──

  async getAuthStatus(): Promise<AuthStatus> {
    const res = await this.request.get(`${BASE_URL}/api/auth/status`);
    return res.json();
  }
}

/** Inject the API key into sessionStorage so the page is authenticated. */
export async function setApiKey(page: Page, apiKey: string): Promise<void> {
  await page.evaluate((key) => {
    sessionStorage.setItem('persea_api_key', key);
  }, apiKey);
}

// ── Types ──

export interface Session {
  session_id: string;
  session_type: string;
  hostname?: string;
  url?: string;
  username?: string;
  status: string;
  active_connections: number;
  created_by?: string;
  client_url: string;
}

export interface SystemStatus {
  version: string;
  sessions: {
    active: number;
    pending: number;
    total_current: number;
  };
  users: {
    count: number;
  };
  history: {
    total_sessions: number;
  };
  recordings: {
    count: number;
    size_mb: number;
    disk_usage_pct: number;
  };
  vault: {
    configured: boolean;
    connected: boolean;
  };
  features: {
    oidc: boolean;
    drive: boolean;
    tls: boolean;
  };
}

export interface User {
  email: string;
  name: string;
  role: string;
  oidc_groups?: string;
  disabled?: boolean;
  last_login_at?: string;
}

export interface Recording {
  name: string;
  user?: string;
  session_type?: string;
  entry_display_name?: string;
  folder?: string;
  size_bytes: number;
  modified?: string;
  created_at?: string;
}

export interface Me {
  name: string;
  role: string;
}

export interface AuthStatus {
  oidc_enabled: boolean;
  site_title?: string;
  theme?: Record<string, unknown>;
}
