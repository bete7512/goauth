// API wrapper - all responses come wrapped in this
export interface ApiResponse<T> {
  data: T;
}

export interface ListResponse<T> {
  list: T[];
  total: number;
  sort_field: string;
  sort_dir: string;
}

// User
export interface User {
  id: string;
  name?: string;
  first_name?: string;
  last_name?: string;
  email: string;
  username?: string;
  avatar?: string;
  phone_number?: string;
  active: boolean;
  email_verified: boolean;
  phone_number_verified: boolean;
  created_at: string;
  updated_at?: string;
  last_login_at?: string;
}

// Auth
export interface AuthResponse {
  access_token?: string;
  refresh_token?: string;
  user?: User;
  expires_in?: number;
  message?: string;
  challenges?: LoginChallenge[];
  data?: Record<string, any>; // module-specific data (orgs, etc.)
}

export interface LoginChallenge {
  type: string;
  data: Record<string, any>;
}

export interface MessageResponse {
  message: string;
}

// Org
export interface OrgInfo {
  id: string;
  name: string;
  slug: string;
  role: string;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  owner_id: string;
  logo_url?: string;
  active: boolean;
  created_at: string;
  updated_at?: string;
}

export interface OrgMember {
  id: string;
  org_id: string;
  user_id: string;
  role: string;
  joined_at: string;
  user?: User;
}

export interface Invitation {
  id: string;
  org_id: string;
  email: string;
  role: string;
  status: string;
  token: string;
  expires_at: string;
  created_at: string;
}

// Session
export interface Session {
  id: string;
  user_agent: string;
  ip_address: string;
  created_at: string;
  expires_at: string;
  current: boolean;
}

// Audit
export interface AuditLog {
  id: string;
  actor_id: string;
  action: string;
  target_id?: string;
  target_type?: string;
  severity: string;
  details?: string;
  ip_address?: string;
  user_agent?: string;
  created_at: string;
}

// 2FA
export interface TwoFactorSetup {
  secret: string;
  qr_url: string;
  backup_codes?: string[];
}

// Check availability
export interface CheckAvailabilityResponse {
  available: boolean;
  field: string;
}

// Requests
export interface SignupRequest {
  name?: string;
  first_name?: string;
  last_name?: string;
  phone_number?: string;
  email: string;
  username?: string;
  password: string;
}

export interface LoginRequest {
  email?: string;
  username?: string;
  password: string;
}

export interface SendVerificationEmailRequest {
  email: string;
}

export interface VerifyPhoneRequest {
  phone: string;
  code: string;
}

export interface ForgotPasswordRequest {
  email?: string;
  phone?: string;
}

export interface ResetPasswordRequest {
  token?: string;
  code?: string;
  email?: string;
  phone?: string;
  new_password: string;
}

export interface UpdateProfileRequest {
  name?: string;
  phone?: string;
  avatar?: string;
}

export interface ChangePasswordRequest {
  old_password: string;
  new_password: string;
}

export interface CheckAvailabilityRequest {
  email?: string;
  username?: string;
  phone?: string;
}
