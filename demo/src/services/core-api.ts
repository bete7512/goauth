import { apiClient } from '@/lib/api-config'
import type {
  SignupRequest,
  LoginRequest,
  AuthResponse,
  User,
  MessageResponse,
  CheckAvailabilityResponse,
  SendVerificationEmailRequest,
  VerifyEmailRequest,
  SendVerificationPhoneRequest,
  VerifyPhoneRequest,
  ForgotPasswordRequest,
  ResetPasswordRequest,
  UpdateProfileRequest,
  ChangePasswordRequest,
  CheckAvailabilityRequest,
} from '@/types/core'

export class CoreApiService {
  // Authentication endpoints
  async signup(data: SignupRequest): Promise<AuthResponse> {
    const url = apiClient.getEndpoint('core', 'signup')
    return apiClient.post<AuthResponse>(url, data)
  }

  async login(data: LoginRequest): Promise<AuthResponse> {
    const url = apiClient.getEndpoint('core', 'login')
    return apiClient.post<AuthResponse>(url, data)
  }

  async logout(token: string): Promise<MessageResponse> {
    const url = apiClient.getEndpoint('core', 'logout')
    return apiClient.post<MessageResponse>(url, {}, {
      'Authorization': `Bearer ${token}`
    })
  }

  async getMe(token: string): Promise<User> {
    const url = apiClient.getEndpoint('core', 'me')
    return apiClient.get<User>(url, {
      'Authorization': `Bearer ${token}`
    })
  }

  // Profile management
  async getProfile(token: string): Promise<User> {
    const url = apiClient.getEndpoint('core', 'profile')
    return apiClient.get<User>(url, {
      'Authorization': `Bearer ${token}`
    })
  }

  async updateProfile(data: UpdateProfileRequest, token: string): Promise<User> {
    const url = apiClient.getEndpoint('core', 'updateProfile')
    return apiClient.put<User>(url, data, {
      'Authorization': `Bearer ${token}`
    })
  }

  async changePassword(data: ChangePasswordRequest, token: string): Promise<MessageResponse> {
    const url = apiClient.getEndpoint('core', 'changePassword')
    return apiClient.put<MessageResponse>(url, data, {
      'Authorization': `Bearer ${token}`
    })
  }

  // Email verification
  async sendVerificationEmail(data: SendVerificationEmailRequest): Promise<MessageResponse> {
    const url = apiClient.getEndpoint('core', 'sendVerificationEmail')
    return apiClient.post<MessageResponse>(url, data)
  }

  async verifyEmail(data: VerifyEmailRequest): Promise<MessageResponse> {
    const url = apiClient.getEndpoint('core', 'verifyEmail')
    return apiClient.post<MessageResponse>(url, data)
  }

  async resendVerificationEmail(data: SendVerificationEmailRequest): Promise<MessageResponse> {
    const url = apiClient.getEndpoint('core', 'resendVerificationEmail')
    return apiClient.post<MessageResponse>(url, data)
  }

  // Phone verification
  async sendVerificationPhone(data: SendVerificationPhoneRequest): Promise<MessageResponse> {
    const url = apiClient.getEndpoint('core', 'sendVerificationPhone')
    return apiClient.post<MessageResponse>(url, data)
  }

  async verifyPhone(data: VerifyPhoneRequest): Promise<MessageResponse> {
    const url = apiClient.getEndpoint('core', 'verifyPhone')
    return apiClient.post<MessageResponse>(url, data)
  }

  async resendVerificationPhone(data: SendVerificationPhoneRequest): Promise<MessageResponse> {
    const url = apiClient.getEndpoint('core', 'resendVerificationPhone')
    return apiClient.post<MessageResponse>(url, data)
  }

  // Password recovery
  async forgotPassword(data: ForgotPasswordRequest): Promise<MessageResponse> {
    const url = apiClient.getEndpoint('core', 'forgotPassword')
    return apiClient.post<MessageResponse>(url, data)
  }

  async resetPassword(data: ResetPasswordRequest): Promise<MessageResponse> {
    const url = apiClient.getEndpoint('core', 'resetPassword')
    return apiClient.post<MessageResponse>(url, data)
  }

  // Availability checks
  async checkEmailAvailability(data: CheckAvailabilityRequest): Promise<CheckAvailabilityResponse> {
    const url = apiClient.getEndpoint('core', 'checkEmailAvailability')
    return apiClient.post<CheckAvailabilityResponse>(url, data)
  }

  async checkUsernameAvailability(data: CheckAvailabilityRequest): Promise<CheckAvailabilityResponse> {
    const url = apiClient.getEndpoint('core', 'checkUsernameAvailability')
    return apiClient.post<CheckAvailabilityResponse>(url, data)
  }

  async checkPhoneAvailability(data: CheckAvailabilityRequest): Promise<CheckAvailabilityResponse> {
    const url = apiClient.getEndpoint('core', 'checkPhoneAvailability')
    return apiClient.post<CheckAvailabilityResponse>(url, data)
  }
}

// Create singleton instance
export const coreApiService = new CoreApiService()






