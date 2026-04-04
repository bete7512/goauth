class ApiClient {
  baseUrl: string;
  private token: string | null = null;
  private refreshToken: string | null = null;

  constructor(baseUrl = 'http://localhost:8080/api/v1') {
    this.baseUrl = baseUrl;
    if (typeof window !== 'undefined') {
      this.token = localStorage.getItem('goauth_token');
      this.refreshToken = localStorage.getItem('goauth_refresh_token');
    }
  }

  getToken(): string | null {
    return this.token;
  }

  getRefreshToken(): string | null {
    return this.refreshToken;
  }

  setToken(token: string | null) {
    this.token = token;
    if (typeof window !== 'undefined') {
      if (token) localStorage.setItem('goauth_token', token);
      else localStorage.removeItem('goauth_token');
    }
  }

  setRefreshToken(token: string | null) {
    this.refreshToken = token;
    if (typeof window !== 'undefined') {
      if (token) localStorage.setItem('goauth_refresh_token', token);
      else localStorage.removeItem('goauth_refresh_token');
    }
  }

  clearTokens() {
    this.setToken(null);
    this.setRefreshToken(null);
  }

  private headers(): Record<string, string> {
    const h: Record<string, string> = { 'Content-Type': 'application/json' };
    if (this.token) h['Authorization'] = `Bearer ${this.token}`;
    return h;
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers: this.headers(),
      body: body ? JSON.stringify(body) : undefined,
    });
    const json = await res.json();
    if (!res.ok) throw new Error(json.message || json.error || `HTTP ${res.status}`);
    // Unwrap the {"data": ...} envelope
    return json.data !== undefined ? json.data : json;
  }

  get<T>(path: string) {
    return this.request<T>('GET', path);
  }

  post<T>(path: string, body?: unknown) {
    return this.request<T>('POST', path, body);
  }

  put<T>(path: string, body?: unknown) {
    return this.request<T>('PUT', path, body);
  }

  del<T>(path: string) {
    return this.request<T>('DELETE', path);
  }
}

export const api = new ApiClient();
