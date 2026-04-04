'use client'

import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { api } from '@/lib/api-client'

interface AdminSectionProps {
  onResponse: (data: unknown) => void
}

export function AdminSection({ onResponse }: AdminSectionProps) {
  const [offset, setOffset] = useState('0')
  const [limit, setLimit] = useState('20')
  const [userId, setUserId] = useState('')

  // Update user fields
  const [updateName, setUpdateName] = useState('')
  const [updateEmail, setUpdateEmail] = useState('')
  const [updateActive, setUpdateActive] = useState('')

  const handleListUsers = async () => {
    try {
      const data = await api.get(`/admin/users?offset=${offset}&limit=${limit}`)
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleGetUser = async () => {
    if (!userId) return
    try {
      const data = await api.get(`/admin/users/${userId}`)
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleUpdateUser = async () => {
    if (!userId) return
    try {
      const body: Record<string, unknown> = {}
      if (updateName) body.name = updateName
      if (updateEmail) body.email = updateEmail
      if (updateActive === 'true') body.active = true
      if (updateActive === 'false') body.active = false
      const data = await api.put(`/admin/users/${userId}`, body)
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleDeleteUser = async () => {
    if (!userId) return
    try {
      const data = await api.del(`/admin/users/${userId}`)
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold">Admin</h2>
        <p className="text-sm text-muted-foreground">User management. Requires admin role.</p>
      </div>

      {/* List Users */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">List Users</CardTitle>
          <CardDescription>GET /admin/users</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex gap-4 items-end">
            <div className="space-y-1">
              <Label>Offset</Label>
              <Input value={offset} onChange={(e) => setOffset(e.target.value)} className="w-24" />
            </div>
            <div className="space-y-1">
              <Label>Limit</Label>
              <Input value={limit} onChange={(e) => setLimit(e.target.value)} className="w-24" />
            </div>
            <Button onClick={handleListUsers}>List Users</Button>
          </div>
        </CardContent>
      </Card>

      {/* User by ID */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">User by ID</CardTitle>
          <CardDescription>GET / PUT / DELETE /admin/users/&#123;id&#125;</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="space-y-1">
            <Label htmlFor="a-uid">User ID</Label>
            <Input id="a-uid" value={userId} onChange={(e) => setUserId(e.target.value)} placeholder="user-uuid" />
          </div>
          <div className="flex gap-3">
            <Button onClick={handleGetUser} variant="outline">Get</Button>
            <Button onClick={handleDeleteUser} variant="destructive">Delete</Button>
          </div>

          <hr className="my-4" />
          <p className="text-sm font-medium">Update User</p>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="space-y-1">
              <Label>Name</Label>
              <Input value={updateName} onChange={(e) => setUpdateName(e.target.value)} placeholder="New name" />
            </div>
            <div className="space-y-1">
              <Label>Email</Label>
              <Input value={updateEmail} onChange={(e) => setUpdateEmail(e.target.value)} placeholder="new@email.com" />
            </div>
            <div className="space-y-1">
              <Label>Active</Label>
              <select
                value={updateActive}
                onChange={(e) => setUpdateActive(e.target.value)}
                className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
              >
                <option value="">-- no change --</option>
                <option value="true">true</option>
                <option value="false">false</option>
              </select>
            </div>
          </div>
          <Button onClick={handleUpdateUser}>Update User</Button>
        </CardContent>
      </Card>
    </div>
  )
}
