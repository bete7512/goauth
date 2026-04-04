'use client'

import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { api } from '@/lib/api-client'

interface SessionsSectionProps {
  onResponse: (data: unknown) => void
}

export function SessionsSection({ onResponse }: SessionsSectionProps) {
  const [sessionId, setSessionId] = useState('')
  const [refreshLoading, setRefreshLoading] = useState(false)

  const handleListSessions = async () => {
    try {
      const data = await api.get('/sessions')
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleGetSession = async () => {
    if (!sessionId) return
    try {
      const data = await api.get(`/sessions/${sessionId}`)
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleDeleteSession = async () => {
    if (!sessionId) return
    try {
      const data = await api.del(`/sessions/${sessionId}`)
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleDeleteAllSessions = async () => {
    try {
      const data = await api.del('/sessions')
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleRefreshToken = async () => {
    const rt = api.getRefreshToken()
    if (!rt) {
      onResponse({ error: 'No refresh token stored. Log in first.' })
      return
    }
    setRefreshLoading(true)
    try {
      const data: any = await api.post('/refresh', { refresh_token: rt })
      onResponse(data)
      // Update both tokens with the rotated values
      if (data.access_token) api.setToken(data.access_token)
      if (data.refresh_token) api.setRefreshToken(data.refresh_token)
    } catch (e: any) {
      onResponse({ error: e.message })
    } finally {
      setRefreshLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold">Sessions</h2>
        <p className="text-sm text-muted-foreground">Manage active sessions. Requires authentication. Only available when session module is active.</p>
      </div>

      <div className="flex gap-3 flex-wrap">
        <Button onClick={handleListSessions}>List Sessions</Button>
        <Button onClick={handleRefreshToken} variant="outline" disabled={refreshLoading}>
          {refreshLoading ? 'Refreshing...' : 'Refresh Token'}
        </Button>
        <Button onClick={handleDeleteAllSessions} variant="destructive">
          Delete All Sessions
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Session by ID</CardTitle>
          <CardDescription>GET / DELETE /sessions/&#123;id&#125;</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="space-y-1">
            <Label htmlFor="sess-id">Session ID</Label>
            <Input id="sess-id" value={sessionId} onChange={(e) => setSessionId(e.target.value)} placeholder="session-uuid" />
          </div>
          <div className="flex gap-3">
            <Button onClick={handleGetSession} variant="outline">Get Session</Button>
            <Button onClick={handleDeleteSession} variant="destructive">Delete Session</Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
