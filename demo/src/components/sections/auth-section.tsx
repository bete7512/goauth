'use client'

import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { api } from '@/lib/api-client'
import type { AuthResponse, User, OrgInfo } from '@/types'

interface AuthSectionProps {
  onLogin: (user: User, token: string, orgs: OrgInfo[]) => void
  onResponse: (data: unknown) => void
}

export function AuthSection({ onLogin, onResponse }: AuthSectionProps) {
  // Signup state
  const [signupEmail, setSignupEmail] = useState('')
  const [signupPassword, setSignupPassword] = useState('')
  const [signupName, setSignupName] = useState('')
  const [signupUsername, setSignupUsername] = useState('')
  const [signupPhone, setSignupPhone] = useState('')
  const [signupError, setSignupError] = useState('')
  const [signupLoading, setSignupLoading] = useState(false)

  // Login state
  const [loginEmail, setLoginEmail] = useState('')
  const [loginPassword, setLoginPassword] = useState('')
  const [loginError, setLoginError] = useState('')
  const [loginLoading, setLoginLoading] = useState(false)

  // Verification state
  const [verifyEmail, setVerifyEmail] = useState('')
  const [forgotEmail, setForgotEmail] = useState('')
  const [resetToken, setResetToken] = useState('')
  const [resetPassword, setResetPassword] = useState('')
  const [availField, setAvailField] = useState<'email' | 'username' | 'phone'>('email')
  const [availValue, setAvailValue] = useState('')

  const handleSignup = async () => {
    setSignupError('')
    setSignupLoading(true)
    try {
      const data = await api.post<AuthResponse>('/signup', {
        email: signupEmail,
        password: signupPassword,
        name: signupName || undefined,
        username: signupUsername || undefined,
        phone_number: signupPhone || undefined,
      })
      onResponse(data)
      if (data.access_token && data.user) {
        api.setToken(data.access_token)
        const orgs = (data.data?.organizations as OrgInfo[]) || []
        onLogin(data.user, data.access_token, orgs)
      }
    } catch (e: any) {
      setSignupError(e.message)
      onResponse({ error: e.message })
    } finally {
      setSignupLoading(false)
    }
  }

  const handleLogin = async () => {
    setLoginError('')
    setLoginLoading(true)
    try {
      const data = await api.post<AuthResponse>('/login', {
        email: loginEmail,
        password: loginPassword,
      })
      onResponse(data)
      if (data.challenges && data.challenges.length > 0) {
        // 2FA challenge - don't complete login yet
        return
      }
      if (data.access_token && data.user) {
        api.setToken(data.access_token)
        const orgs = (data.data?.organizations as OrgInfo[]) || []
        onLogin(data.user, data.access_token, orgs)
      }
    } catch (e: any) {
      setLoginError(e.message)
      onResponse({ error: e.message })
    } finally {
      setLoginLoading(false)
    }
  }

  const handleSendVerification = async () => {
    try {
      const data = await api.post('/send-verification-email', { email: verifyEmail })
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleForgotPassword = async () => {
    try {
      const data = await api.post('/forgot-password', { email: forgotEmail })
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleResetPassword = async () => {
    try {
      const data = await api.post('/reset-password', {
        token: resetToken,
        new_password: resetPassword,
      })
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleCheckAvailability = async () => {
    try {
      const body: Record<string, string> = {}
      body[availField] = availValue
      const data = await api.post('/is-available', body)
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold">Authentication</h2>
        <p className="text-sm text-muted-foreground">Signup, login, and account verification.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Signup */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Signup</CardTitle>
            <CardDescription>POST /signup</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="space-y-1">
              <Label htmlFor="s-email">Email *</Label>
              <Input id="s-email" type="email" value={signupEmail} onChange={(e) => setSignupEmail(e.target.value)} placeholder="user@example.com" />
            </div>
            <div className="space-y-1">
              <Label htmlFor="s-password">Password *</Label>
              <Input id="s-password" type="password" value={signupPassword} onChange={(e) => setSignupPassword(e.target.value)} placeholder="min 8 chars" />
            </div>
            <div className="space-y-1">
              <Label htmlFor="s-name">Name</Label>
              <Input id="s-name" value={signupName} onChange={(e) => setSignupName(e.target.value)} placeholder="John Doe" />
            </div>
            <div className="space-y-1">
              <Label htmlFor="s-username">Username</Label>
              <Input id="s-username" value={signupUsername} onChange={(e) => setSignupUsername(e.target.value)} placeholder="johndoe" />
            </div>
            <div className="space-y-1">
              <Label htmlFor="s-phone">Phone</Label>
              <Input id="s-phone" value={signupPhone} onChange={(e) => setSignupPhone(e.target.value)} placeholder="+1234567890" />
            </div>
            {signupError && <p className="text-sm text-red-600">{signupError}</p>}
            <Button onClick={handleSignup} disabled={signupLoading} className="w-full">
              {signupLoading ? 'Signing up...' : 'Sign Up'}
            </Button>
          </CardContent>
        </Card>

        {/* Login */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Login</CardTitle>
            <CardDescription>POST /login</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="space-y-1">
              <Label htmlFor="l-email">Email</Label>
              <Input id="l-email" type="email" value={loginEmail} onChange={(e) => setLoginEmail(e.target.value)} placeholder="user@example.com" />
            </div>
            <div className="space-y-1">
              <Label htmlFor="l-password">Password</Label>
              <Input id="l-password" type="password" value={loginPassword} onChange={(e) => setLoginPassword(e.target.value)} />
            </div>
            {loginError && <p className="text-sm text-red-600">{loginError}</p>}
            <Button onClick={handleLogin} disabled={loginLoading} className="w-full">
              {loginLoading ? 'Logging in...' : 'Log In'}
            </Button>
          </CardContent>
        </Card>
      </div>

      {/* Verification & Password Reset */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Send Verification Email */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Email Verification</CardTitle>
            <CardDescription>POST /send-verification-email</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="space-y-1">
              <Label htmlFor="v-email">Email</Label>
              <Input id="v-email" type="email" value={verifyEmail} onChange={(e) => setVerifyEmail(e.target.value)} placeholder="user@example.com" />
            </div>
            <Button onClick={handleSendVerification} variant="outline" className="w-full">
              Send Verification
            </Button>
          </CardContent>
        </Card>

        {/* Forgot Password */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Forgot Password</CardTitle>
            <CardDescription>POST /forgot-password</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="space-y-1">
              <Label htmlFor="f-email">Email</Label>
              <Input id="f-email" type="email" value={forgotEmail} onChange={(e) => setForgotEmail(e.target.value)} placeholder="user@example.com" />
            </div>
            <Button onClick={handleForgotPassword} variant="outline" className="w-full">
              Send Reset Link
            </Button>
          </CardContent>
        </Card>

        {/* Reset Password */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Reset Password</CardTitle>
            <CardDescription>POST /reset-password</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="space-y-1">
              <Label htmlFor="r-token">Reset Token</Label>
              <Input id="r-token" value={resetToken} onChange={(e) => setResetToken(e.target.value)} placeholder="token from email" />
            </div>
            <div className="space-y-1">
              <Label htmlFor="r-password">New Password</Label>
              <Input id="r-password" type="password" value={resetPassword} onChange={(e) => setResetPassword(e.target.value)} />
            </div>
            <Button onClick={handleResetPassword} variant="outline" className="w-full">
              Reset Password
            </Button>
          </CardContent>
        </Card>
      </div>

      {/* Check Availability */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Check Availability</CardTitle>
          <CardDescription>POST /is-available</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex gap-4 items-end">
            <div className="space-y-1">
              <Label>Field</Label>
              <select
                value={availField}
                onChange={(e) => setAvailField(e.target.value as 'email' | 'username' | 'phone')}
                className="flex h-10 rounded-md border border-input bg-background px-3 py-2 text-sm"
              >
                <option value="email">Email</option>
                <option value="username">Username</option>
                <option value="phone">Phone</option>
              </select>
            </div>
            <div className="space-y-1 flex-1">
              <Label>Value</Label>
              <Input value={availValue} onChange={(e) => setAvailValue(e.target.value)} placeholder={`Enter ${availField}`} />
            </div>
            <Button onClick={handleCheckAvailability} variant="outline">
              Check
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
