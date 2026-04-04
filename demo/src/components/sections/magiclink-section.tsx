'use client'

import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { api } from '@/lib/api-client'
import type { AuthResponse, User, OrgInfo } from '@/types'

interface MagicLinkSectionProps {
  onLogin: (user: User, token: string, orgs: OrgInfo[]) => void
  onResponse: (data: unknown) => void
}

export function MagicLinkSection({ onLogin, onResponse }: MagicLinkSectionProps) {
  const [sendEmail, setSendEmail] = useState('')
  const [verifyToken, setVerifyToken] = useState('')
  const [verifyCode, setVerifyCode] = useState('')
  const [verifyEmail, setVerifyEmail] = useState('')
  const [resendEmail, setResendEmail] = useState('')

  const handleSend = async () => {
    try {
      const data = await api.post('/magic-link/send', { email: sendEmail })
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleVerifyToken = async () => {
    try {
      const data = await api.get<AuthResponse>(`/magic-link/verify?token=${encodeURIComponent(verifyToken)}`)
      onResponse(data)
      if (data.access_token && data.user) {
        api.setToken(data.access_token)
        const orgs = (data.data?.organizations as OrgInfo[]) || []
        onLogin(data.user, data.access_token, orgs)
      }
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleVerifyCode = async () => {
    try {
      const data = await api.post<AuthResponse>('/magic-link/verify-code', {
        email: verifyEmail,
        code: verifyCode,
      })
      onResponse(data)
      if (data.access_token && data.user) {
        api.setToken(data.access_token)
        const orgs = (data.data?.organizations as OrgInfo[]) || []
        onLogin(data.user, data.access_token, orgs)
      }
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleResend = async () => {
    try {
      const data = await api.post('/magic-link/resend', { email: resendEmail })
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold">Magic Link</h2>
        <p className="text-sm text-muted-foreground">Passwordless authentication via email magic link or code.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Send Magic Link */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Send Magic Link</CardTitle>
            <CardDescription>POST /magic-link/send</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="space-y-1">
              <Label>Email</Label>
              <Input value={sendEmail} onChange={(e) => setSendEmail(e.target.value)} placeholder="user@example.com" />
            </div>
            <Button onClick={handleSend} className="w-full">Send Magic Link</Button>
          </CardContent>
        </Card>

        {/* Resend */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Resend Magic Link</CardTitle>
            <CardDescription>POST /magic-link/resend</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="space-y-1">
              <Label>Email</Label>
              <Input value={resendEmail} onChange={(e) => setResendEmail(e.target.value)} placeholder="user@example.com" />
            </div>
            <Button onClick={handleResend} variant="outline" className="w-full">Resend</Button>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Verify by Token */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Verify by Token</CardTitle>
            <CardDescription>GET /magic-link/verify?token=xxx</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="space-y-1">
              <Label>Token (from email link)</Label>
              <Input value={verifyToken} onChange={(e) => setVerifyToken(e.target.value)} placeholder="magic-link-token" />
            </div>
            <Button onClick={handleVerifyToken} className="w-full">Verify Token</Button>
          </CardContent>
        </Card>

        {/* Verify by Code */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Verify by Code</CardTitle>
            <CardDescription>POST /magic-link/verify-code</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="space-y-1">
              <Label>Email</Label>
              <Input value={verifyEmail} onChange={(e) => setVerifyEmail(e.target.value)} placeholder="user@example.com" />
            </div>
            <div className="space-y-1">
              <Label>Code</Label>
              <Input value={verifyCode} onChange={(e) => setVerifyCode(e.target.value)} placeholder="6-digit code" />
            </div>
            <Button onClick={handleVerifyCode} className="w-full">Verify Code</Button>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
