// Core Module Types - Based on Go Auth DTOs
export interface ExtendedAttribute {
  name: string
  value: string
}

export interface User {
  id: string
  first_name?: string
  last_name?: string
  name?: string
  email: string
  username?: string
  avatar?: string
  phone_number?: string
  active: boolean
  email_verified: boolean
  phone_number_verified: boolean
  created_at: string
  updated_at: string
  extended_attributes?: ExtendedAttribute[]
}

export interface AuthResponse {
  token?: string
  refresh_token?: string
  user: User
  expires_in?: number
  message?: string
}

export interface MessageResponse {
  message: string
  success: boolean
}

export interface ErrorResponse {
  error: string
  message?: string
  code?: number
}

export interface CheckAvailabilityResponse {
  available: boolean
  field: string
  message?: string
}

// Request Types
export interface SignupRequest {
  name?: string
  first_name?: string
  last_name?: string
  phone_number?: string
  email: string
  username?: string
  password: string
  extended_attributes?: ExtendedAttribute[]
}

export interface LoginRequest {
  email?: string
  username?: string
  password: string
}

export interface SendVerificationEmailRequest {
  email: string
}

export interface VerifyEmailRequest {
  token: string
  email: string
}

export interface SendVerificationPhoneRequest {
  phone: string
}

export interface VerifyPhoneRequest {
  phone: string
  code: string
}

export interface ForgotPasswordRequest {
  email?: string
  phone?: string
}

export interface ResetPasswordRequest {
  token?: string
  code?: string
  email?: string
  phone?: string
  new_password: string
}

export interface UpdateProfileRequest {
  name?: string
  phone?: string
  avatar?: string
}

export interface ChangePasswordRequest {
  old_password: string
  new_password: string
}

export interface CheckAvailabilityRequest {
  email?: string
  username?: string
  phone?: string
}






