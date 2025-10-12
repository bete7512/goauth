// Configuration file for easy updates
// Update these values to match your Go-Auth server configuration

export const DEMO_CONFIG = {
  // API Server Configuration
  api: {
    baseUrl: 'http://localhost:8080',
    basePath: '/api/v1',
    timeout: 10000,
  },
  
  // Feature Flags
  features: {
    enableEmailVerification: true,
    enablePhoneVerification: true,
    enableUsername: true,
    enablePhoneNumber: true,
    enableExtendedAttributes: true,
  },
  
  // UI Configuration
  ui: {
    showApiInfo: true,
    showUserStatus: true,
    enableTabs: ['signup', 'login', 'forgot-password', 'availability'],
  },
  
  // Validation Rules
  validation: {
    passwordMinLength: 8,
    usernameMinLength: 3,
    usernameMaxLength: 30,
    phoneFormat: 'E.164', // +1234567890
  },
  
  // Demo Messages
  messages: {
    welcome: 'Welcome to Go-Auth Demo!',
    signupSuccess: 'Account created successfully!',
    loginSuccess: 'Logged in successfully!',
    logoutSuccess: 'Logged out successfully!',
    errorGeneric: 'An error occurred. Please try again.',
  }
} as const

// Helper function to get full API URL
export function getApiUrl(endpoint: string): string {
  return `${DEMO_CONFIG.api.baseUrl}${DEMO_CONFIG.api.basePath}${endpoint}`
}

// Helper function to check if feature is enabled
export function isFeatureEnabled(feature: keyof typeof DEMO_CONFIG.features): boolean {
  return DEMO_CONFIG.features[feature]
}

// Helper function to get validation rules
export function getValidationRules() {
  return DEMO_CONFIG.validation
}
