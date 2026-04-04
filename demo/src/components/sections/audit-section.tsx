'use client'

import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { api } from '@/lib/api-client'

interface AuditSectionProps {
  onResponse: (data: unknown) => void
}

export function AuditSection({ onResponse }: AuditSectionProps) {
  const [adminUserId, setAdminUserId] = useState('')

  const handleMyAuditLogs = async () => {
    try {
      const data = await api.get('/audit/me')
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleMyLogins = async () => {
    try {
      const data = await api.get('/audit/me/logins')
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleMyChanges = async () => {
    try {
      const data = await api.get('/audit/me/changes')
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleMySecurity = async () => {
    try {
      const data = await api.get('/audit/me/security')
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleAdminAllLogs = async () => {
    try {
      const data = await api.get('/admin/audit')
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleAdminUserLogs = async () => {
    if (!adminUserId) return
    try {
      const data = await api.get(`/admin/audit/users/${adminUserId}`)
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleCleanup = async () => {
    try {
      const data = await api.post('/admin/audit/cleanup')
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold">Audit</h2>
        <p className="text-sm text-muted-foreground">View audit logs. Requires authentication.</p>
      </div>

      {/* My Audit Logs */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">My Audit Logs</CardTitle>
          <CardDescription>Endpoints under /audit/me</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex gap-3 flex-wrap">
            <Button onClick={handleMyAuditLogs} variant="outline">All My Logs</Button>
            <Button onClick={handleMyLogins} variant="outline">My Logins</Button>
            <Button onClick={handleMyChanges} variant="outline">My Changes</Button>
            <Button onClick={handleMySecurity} variant="outline">My Security</Button>
          </div>
        </CardContent>
      </Card>

      {/* Admin Audit */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Admin Audit</CardTitle>
          <CardDescription>Requires admin role</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex gap-3 flex-wrap">
            <Button onClick={handleAdminAllLogs}>All Audit Logs</Button>
            <Button onClick={handleCleanup} variant="destructive">Cleanup Old Logs</Button>
          </div>

          <hr className="my-4" />
          <div className="flex gap-4 items-end">
            <div className="space-y-1 flex-1">
              <Label>User ID</Label>
              <Input value={adminUserId} onChange={(e) => setAdminUserId(e.target.value)} placeholder="user-uuid" />
            </div>
            <Button onClick={handleAdminUserLogs} variant="outline">Get User Logs</Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
