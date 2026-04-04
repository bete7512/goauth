'use client'

import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { api } from '@/lib/api-client'

interface SettingsSectionProps {
  onResponse: (data: unknown) => void
}

export function SettingsSection({ onResponse }: SettingsSectionProps) {
  const [baseUrl, setBaseUrl] = useState(api.baseUrl)
  const [saved, setSaved] = useState(false)

  const handleSave = () => {
    api.baseUrl = baseUrl
    setSaved(true)
    onResponse({ message: 'API base URL updated', baseUrl })
    setTimeout(() => setSaved(false), 2000)
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold">Settings</h2>
        <p className="text-sm text-muted-foreground">Configure the API connection for this demo.</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">API Configuration</CardTitle>
          <CardDescription>Set the base URL for the GoAuth API server.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="baseUrl">Base URL</Label>
            <Input
              id="baseUrl"
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              placeholder="http://localhost:8080/api/v1"
            />
            <p className="text-xs text-muted-foreground">
              Include the full path prefix, e.g. http://localhost:8080/api/v1
            </p>
          </div>
          <Button onClick={handleSave}>
            {saved ? 'Saved' : 'Save'}
          </Button>
        </CardContent>
      </Card>
    </div>
  )
}
