'use client'

import { useState } from 'react'
import { QRCodeSVG } from 'qrcode.react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { api } from '@/lib/api-client'

interface TwoFactorSectionProps {
  onResponse: (data: unknown) => void
  tempToken?: string  // Auto-filled from login 2FA challenge
  onLoginSuccess?: (data: any) => void  // Called after successful 2FA verify-login
}

export function TwoFactorSection({ onResponse, tempToken: initialTempToken, onLoginSuccess }: TwoFactorSectionProps) {
  const [setupCode, setSetupCode] = useState('')
  const [loginCode, setLoginCode] = useState('')
  const [loginTempToken, setLoginTempToken] = useState(initialTempToken || '')
  const [disableCode, setDisableCode] = useState('')
  const [qrUrl, setQrUrl] = useState('')
  const [secret, setSecret] = useState('')

  const handleSetup = async () => {
    try {
      const data = await api.post<{ secret?: string; qr_url?: string }>('/2fa/setup')
      onResponse(data)
      if (data.qr_url) setQrUrl(data.qr_url)
      if (data.secret) setSecret(data.secret)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleVerifySetup = async () => {
    try {
      const data = await api.post('/2fa/verify', { code: setupCode })
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleVerifyLogin = async () => {
    if (!loginTempToken) {
      onResponse({ error: 'No temp_token. Log in first to get a 2FA challenge.' })
      return
    }
    try {
      const data: any = await api.post('/2fa/verify-login', {
        temp_token: loginTempToken,
        code: loginCode,
      })
      onResponse(data)
      // On success, update tokens
      if (data.access_token) {
        api.setToken(data.access_token)
        if (data.refresh_token) api.setRefreshToken(data.refresh_token)
        onLoginSuccess?.(data)
      }
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleDisable = async () => {
    try {
      const data = await api.post('/2fa/disable', { code: disableCode })
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleStatus = async () => {
    try {
      const data = await api.get('/2fa/status')
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold">Two-Factor Authentication</h2>
        <p className="text-sm text-muted-foreground">Setup and manage TOTP-based 2FA. Requires authentication.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Setup */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Setup 2FA</CardTitle>
            <CardDescription>POST /2fa/setup, POST /2fa/verify</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <Button onClick={handleSetup} className="w-full">Start Setup</Button>

            {qrUrl && (
              <div className="space-y-3">
                <p className="text-sm font-medium">Scan this QR code with your authenticator app:</p>
                <div className="p-4 bg-white border rounded flex justify-center">
                  <QRCodeSVG value={qrUrl} size={200} />
                </div>
                {secret && (
                  <div className="space-y-1">
                    <p className="text-xs text-muted-foreground">Or enter this secret manually:</p>
                    <code className="block text-xs bg-gray-100 p-2 rounded font-mono break-all select-all">{secret}</code>
                  </div>
                )}
              </div>
            )}

            <hr className="my-2" />
            <div className="space-y-1">
              <Label>Verification Code</Label>
              <Input value={setupCode} onChange={(e) => setSetupCode(e.target.value)} placeholder="6-digit code" />
            </div>
            <Button onClick={handleVerifySetup} variant="outline" className="w-full">Verify Setup</Button>
          </CardContent>
        </Card>

        {/* Verify Login */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Verify 2FA Login</CardTitle>
            <CardDescription>POST /2fa/verify-login</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground">
              Use this after login returns a 2FA challenge. The temp_token is auto-filled from the challenge response.
            </p>
            <div className="space-y-1">
              <Label>Temp Token</Label>
              <Input
                value={loginTempToken}
                onChange={(e) => setLoginTempToken(e.target.value)}
                placeholder="From login challenge response"
                className="font-mono text-xs"
              />
            </div>
            <div className="space-y-1">
              <Label>2FA Code</Label>
              <Input value={loginCode} onChange={(e) => setLoginCode(e.target.value)} placeholder="6-digit code or backup code" />
            </div>
            <Button onClick={handleVerifyLogin} className="w-full">Verify Login</Button>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Disable */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Disable 2FA</CardTitle>
            <CardDescription>POST /2fa/disable</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="space-y-1">
              <Label>Current 2FA Code</Label>
              <Input value={disableCode} onChange={(e) => setDisableCode(e.target.value)} placeholder="6-digit code" />
            </div>
            <Button onClick={handleDisable} variant="destructive" className="w-full">Disable 2FA</Button>
          </CardContent>
        </Card>

        {/* Status */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">2FA Status</CardTitle>
            <CardDescription>GET /2fa/status</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground">Check if 2FA is enabled and view configuration.</p>
            <Button onClick={handleStatus} variant="outline" className="w-full">Check Status</Button>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
