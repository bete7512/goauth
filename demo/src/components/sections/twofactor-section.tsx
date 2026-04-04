'use client'

import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { api } from '@/lib/api-client'

interface TwoFactorSectionProps {
  onResponse: (data: unknown) => void
}

export function TwoFactorSection({ onResponse }: TwoFactorSectionProps) {
  const [setupCode, setSetupCode] = useState('')
  const [loginCode, setLoginCode] = useState('')
  const [disableCode, setDisableCode] = useState('')
  const [qrUrl, setQrUrl] = useState('')

  const handleSetup = async () => {
    try {
      const data = await api.post<{ secret?: string; qr_url?: string }>('/2fa/setup')
      onResponse(data)
      if (data.qr_url) setQrUrl(data.qr_url)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleVerifySetup = async () => {
    try {
      const data = await api.post('/2fa/verify-setup', { code: setupCode })
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleVerifyLogin = async () => {
    try {
      const data = await api.post('/2fa/verify-login', { code: loginCode })
      onResponse(data)
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

  const handleGetBackupCodes = async () => {
    try {
      const data = await api.get('/2fa/backup-codes')
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleRegenerateBackupCodes = async () => {
    try {
      const data = await api.post('/2fa/regenerate-backup-codes')
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
            <CardDescription>POST /2fa/setup, POST /2fa/verify-setup</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <Button onClick={handleSetup} className="w-full">Start Setup</Button>

            {qrUrl && (
              <div className="space-y-2">
                <p className="text-sm font-medium">Scan this QR code with your authenticator app:</p>
                <div className="p-2 bg-white border rounded flex justify-center">
                  {/* eslint-disable-next-line @next/next/no-img-element */}
                  <img src={qrUrl} alt="2FA QR Code" className="max-w-[200px]" />
                </div>
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
              Use this after login returns a 2FA challenge.
            </p>
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

        {/* Backup Codes */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Backup Codes</CardTitle>
            <CardDescription>GET /2fa/backup-codes, POST /2fa/regenerate-backup-codes</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <Button onClick={handleGetBackupCodes} variant="outline" className="w-full">View Backup Codes</Button>
            <Button onClick={handleRegenerateBackupCodes} variant="outline" className="w-full">Regenerate Backup Codes</Button>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
