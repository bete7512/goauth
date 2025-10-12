// API Configuration
export interface ApiConfig {
  baseUrl: string
  basePath: string
  timeout: number
}

export const defaultApiConfig: ApiConfig = {
  baseUrl: 'http://localhost:8080',
  basePath: '/api/v1',
  timeout: 10000,
}

// Module Configuration
export interface ModuleConfig {
  name: string
  enabled: boolean
  endpoints: Record<string, string>
}

export interface GoAuthModules {
  core: ModuleConfig
  oauth?: ModuleConfig
  twofactor?: ModuleConfig
  magiclink?: ModuleConfig
  notification?: ModuleConfig
  captcha?: ModuleConfig
  csrf?: ModuleConfig
  ratelimiter?: ModuleConfig
  admin?: ModuleConfig
}

export const defaultModules: GoAuthModules = {
  core: {
    name: 'core',
    enabled: true,
    endpoints: {
      signup: '/signup',
      login: '/login',
      logout: '/logout',
      me: '/me',
      profile: '/profile',
      updateProfile: '/profile',
      changePassword: '/change-password',
      sendVerificationEmail: '/send-verification-email',
      verifyEmail: '/verify-email',
      sendVerificationPhone: '/send-verification-phone',
      verifyPhone: '/verify-phone',
      forgotPassword: '/forgot-password',
      resetPassword: '/reset-password',
      checkEmailAvailability: '/availability/email',
      checkUsernameAvailability: '/availability/username',
      checkPhoneAvailability: '/availability/phone',
      resendVerificationEmail: '/resend-verification-email',
      resendVerificationPhone: '/resend-verification-phone',
    }
  }
}

// API Client Configuration
export class ApiClient {
  private config: ApiConfig
  private modules: GoAuthModules

  constructor(config: Partial<ApiConfig> = {}, modules: Partial<GoAuthModules> = {}) {
    this.config = { ...defaultApiConfig, ...config }
    this.modules = { ...defaultModules, ...modules }
  }

  updateConfig(newConfig: Partial<ApiConfig>) {
    this.config = { ...this.config, ...newConfig }
  }

  getBaseUrl(): string {
    return `${this.config.baseUrl}${this.config.basePath}`
  }

  getEndpoint(module: keyof GoAuthModules, endpoint: string): string {
    const moduleConfig = this.modules[module]
    if (!moduleConfig || !moduleConfig.enabled) {
      throw new Error(`Module ${module} is not enabled`)
    }
    
    const endpointPath = moduleConfig.endpoints[endpoint]
    if (!endpointPath) {
      throw new Error(`Endpoint ${endpoint} not found in module ${module}`)
    }
    
    return `${this.getBaseUrl()}${endpointPath}`
  }

  async request<T>(
    url: string,
    options: RequestInit = {}
  ): Promise<T> {
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeout)

    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
        headers: {
          'Content-Type': 'application/json',
          ...options.headers,
        },
      })

      clearTimeout(timeoutId)

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}))
        throw new Error(errorData.message || `HTTP ${response.status}`)
      }

      return await response.json()
    } catch (error) {
      clearTimeout(timeoutId)
      throw error
    }
  }

  // Helper methods for common HTTP methods
  async get<T>(url: string, headers?: Record<string, string>): Promise<T> {
    return this.request<T>(url, { method: 'GET', headers })
  }

  async post<T>(url: string, data?: any, headers?: Record<string, string>): Promise<T> {
    return this.request<T>(url, {
      method: 'POST',
      body: data ? JSON.stringify(data) : undefined,
      headers,
    })
  }

  async put<T>(url: string, data?: any, headers?: Record<string, string>): Promise<T> {
    return this.request<T>(url, {
      method: 'PUT',
      body: data ? JSON.stringify(data) : undefined,
      headers,
    })
  }

  async delete<T>(url: string, headers?: Record<string, string>): Promise<T> {
    return this.request<T>(url, { method: 'DELETE', headers })
  }
}

// Create default API client instance
export const apiClient = new ApiClient()
