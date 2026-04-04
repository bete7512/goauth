'use client'

import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { api } from '@/lib/api-client'
import type { OrgInfo } from '@/types'

interface OrgSectionProps {
  organizations: OrgInfo[]
  activeOrg: OrgInfo | null
  onOrgSwitch: (org: OrgInfo) => void
  onOrgsUpdate: (orgs: OrgInfo[]) => void
  onResponse: (data: unknown) => void
}

export function OrgSection({ organizations, activeOrg, onOrgSwitch, onOrgsUpdate, onResponse }: OrgSectionProps) {
  // Create org
  const [orgName, setOrgName] = useState('')
  const [orgSlug, setOrgSlug] = useState('')

  // Org operations
  const [orgId, setOrgId] = useState('')
  const [updateOrgName, setUpdateOrgName] = useState('')

  // Members
  const [memberUserId, setMemberUserId] = useState('')
  const [memberRole, setMemberRole] = useState('')

  // Invite
  const [inviteEmail, setInviteEmail] = useState('')
  const [inviteRole, setInviteRole] = useState('member')
  const [invitationId, setInvitationId] = useState('')

  // Accept/Decline
  const [invToken, setInvToken] = useState('')

  const selectedOrgId = orgId || activeOrg?.id || ''

  const handleCreateOrg = async () => {
    try {
      const data = await api.post('/org', {
        name: orgName,
        slug: orgSlug || undefined,
      })
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleListMyOrgs = async () => {
    try {
      const data = await api.get('/org/my')
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleSwitchOrg = async (targetOrgId: string) => {
    try {
      const data = await api.post('/org/switch', { org_id: targetOrgId })
      onResponse(data)
      const org = organizations.find(o => o.id === targetOrgId)
      if (org) onOrgSwitch(org)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleGetOrg = async () => {
    if (!selectedOrgId) return
    try {
      const data = await api.get(`/org/${selectedOrgId}`)
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleUpdateOrg = async () => {
    if (!selectedOrgId) return
    try {
      const data = await api.put(`/org/${selectedOrgId}`, { name: updateOrgName })
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleDeleteOrg = async () => {
    if (!selectedOrgId) return
    try {
      const data = await api.del(`/org/${selectedOrgId}`)
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleListMembers = async () => {
    if (!selectedOrgId) return
    try {
      const data = await api.get(`/org/${selectedOrgId}/members`)
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleGetMember = async () => {
    if (!selectedOrgId || !memberUserId) return
    try {
      const data = await api.get(`/org/${selectedOrgId}/members/${memberUserId}`)
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleUpdateMember = async () => {
    if (!selectedOrgId || !memberUserId) return
    try {
      const data = await api.put(`/org/${selectedOrgId}/members/${memberUserId}`, { role: memberRole })
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleRemoveMember = async () => {
    if (!selectedOrgId || !memberUserId) return
    try {
      const data = await api.del(`/org/${selectedOrgId}/members/${memberUserId}`)
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleInvite = async () => {
    if (!selectedOrgId) return
    try {
      const data = await api.post(`/org/${selectedOrgId}/invite`, {
        email: inviteEmail,
        role: inviteRole,
      })
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleListInvitations = async () => {
    if (!selectedOrgId) return
    try {
      const data = await api.get(`/org/${selectedOrgId}/invitations`)
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleCancelInvitation = async () => {
    if (!selectedOrgId || !invitationId) return
    try {
      const data = await api.del(`/org/${selectedOrgId}/invitations/${invitationId}`)
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleMyInvitations = async () => {
    try {
      const data = await api.get('/org/my/invitations')
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleAcceptInvitation = async () => {
    try {
      const data = await api.post('/org/invitations/accept', { token: invToken })
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleDeclineInvitation = async () => {
    try {
      const data = await api.post('/org/invitations/decline', { token: invToken })
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold">Organizations</h2>
        <p className="text-sm text-muted-foreground">Manage organizations, members, and invitations. Requires authentication.</p>
      </div>

      {/* Active org indicator */}
      {activeOrg && (
        <div className="text-sm p-3 bg-muted rounded-lg">
          Active org: <span className="font-medium">{activeOrg.name}</span> ({activeOrg.role}) - ID: <code className="text-xs">{activeOrg.id}</code>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Create Org */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Create Organization</CardTitle>
            <CardDescription>POST /org</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="space-y-1">
              <Label>Name</Label>
              <Input value={orgName} onChange={(e) => setOrgName(e.target.value)} placeholder="My Organization" />
            </div>
            <div className="space-y-1">
              <Label>Slug (optional)</Label>
              <Input value={orgSlug} onChange={(e) => setOrgSlug(e.target.value)} placeholder="my-org" />
            </div>
            <Button onClick={handleCreateOrg} className="w-full">Create</Button>
          </CardContent>
        </Card>

        {/* My Orgs & Switch */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">My Organizations</CardTitle>
            <CardDescription>GET /org/my, POST /org/switch</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <Button onClick={handleListMyOrgs} className="w-full">List My Orgs</Button>
            {organizations.length > 0 && (
              <div className="space-y-2">
                <p className="text-sm font-medium">Switch Organization:</p>
                {organizations.map((org) => (
                  <button
                    key={org.id}
                    onClick={() => handleSwitchOrg(org.id)}
                    className={`w-full text-left p-2 rounded border text-sm ${
                      activeOrg?.id === org.id ? 'border-primary bg-muted' : 'border-input hover:bg-muted/50'
                    }`}
                  >
                    {org.name} ({org.role})
                  </button>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Org Details */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Organization Details</CardTitle>
          <CardDescription>GET / PUT / DELETE /org/&#123;orgId&#125;</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="space-y-1">
            <Label>Org ID (defaults to active org)</Label>
            <Input value={orgId} onChange={(e) => setOrgId(e.target.value)} placeholder={activeOrg?.id || 'org-uuid'} />
          </div>
          <div className="flex gap-3">
            <Button onClick={handleGetOrg} variant="outline">Get Org</Button>
            <Button onClick={handleDeleteOrg} variant="destructive">Delete Org</Button>
          </div>
          <hr className="my-2" />
          <div className="flex gap-3 items-end">
            <div className="space-y-1 flex-1">
              <Label>New Name</Label>
              <Input value={updateOrgName} onChange={(e) => setUpdateOrgName(e.target.value)} placeholder="Updated Name" />
            </div>
            <Button onClick={handleUpdateOrg}>Update</Button>
          </div>
        </CardContent>
      </Card>

      {/* Members */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Members</CardTitle>
          <CardDescription>Manage org members (uses org ID above)</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <Button onClick={handleListMembers} variant="outline">List Members</Button>

          <hr className="my-2" />
          <div className="space-y-1">
            <Label>Member User ID</Label>
            <Input value={memberUserId} onChange={(e) => setMemberUserId(e.target.value)} placeholder="user-uuid" />
          </div>
          <div className="flex gap-3 items-end">
            <div className="space-y-1 flex-1">
              <Label>Role</Label>
              <Input value={memberRole} onChange={(e) => setMemberRole(e.target.value)} placeholder="admin / member" />
            </div>
            <Button onClick={handleGetMember} variant="outline">Get</Button>
            <Button onClick={handleUpdateMember} variant="outline">Update Role</Button>
            <Button onClick={handleRemoveMember} variant="destructive">Remove</Button>
          </div>
        </CardContent>
      </Card>

      {/* Invitations */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Send Invitation</CardTitle>
            <CardDescription>POST /org/&#123;orgId&#125;/invite</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="space-y-1">
              <Label>Email</Label>
              <Input value={inviteEmail} onChange={(e) => setInviteEmail(e.target.value)} placeholder="user@example.com" />
            </div>
            <div className="space-y-1">
              <Label>Role</Label>
              <Input value={inviteRole} onChange={(e) => setInviteRole(e.target.value)} placeholder="member" />
            </div>
            <Button onClick={handleInvite} className="w-full">Invite</Button>

            <hr className="my-2" />
            <Button onClick={handleListInvitations} variant="outline" className="w-full">List Invitations</Button>
            <div className="flex gap-3 items-end">
              <div className="space-y-1 flex-1">
                <Label>Invitation ID</Label>
                <Input value={invitationId} onChange={(e) => setInvitationId(e.target.value)} placeholder="invitation-uuid" />
              </div>
              <Button onClick={handleCancelInvitation} variant="destructive">Cancel</Button>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">My Invitations</CardTitle>
            <CardDescription>Accept or decline pending invitations</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <Button onClick={handleMyInvitations} variant="outline" className="w-full">List My Invitations</Button>

            <hr className="my-2" />
            <div className="space-y-1">
              <Label>Invitation Token</Label>
              <Input value={invToken} onChange={(e) => setInvToken(e.target.value)} placeholder="token from invitation" />
            </div>
            <div className="flex gap-3">
              <Button onClick={handleAcceptInvitation} className="flex-1">Accept</Button>
              <Button onClick={handleDeclineInvitation} variant="outline" className="flex-1">Decline</Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
