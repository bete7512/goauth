'use client'

import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { api } from '@/lib/api-client'

interface ProfileSectionProps {
  onResponse: (data: unknown) => void
}

export function ProfileSection({ onResponse }: ProfileSectionProps) {
  // Edit profile state
  const [name, setName] = useState('')
  const [phone, setPhone] = useState('')
  const [avatar, setAvatar] = useState('')

  // Change password state
  const [oldPassword, setOldPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')

  // Phone verification
  const [verifyPhone, setVerifyPhone] = useState('')
  const [verifyCode, setVerifyCode] = useState('')

  const handleGetMe = async () => {
    try {
      const data = await api.get('/me')
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleUpdateProfile = async () => {
    try {
      const body: Record<string, string> = {}
      if (name) body.name = name
      if (phone) body.phone = phone
      if (avatar) body.avatar = avatar
      const data = await api.put('/profile', body)
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleChangePassword = async () => {
    try {
      const data = await api.put('/change-password', {
        old_password: oldPassword,
        new_password: newPassword,
      })
      onResponse(data)
      setOldPassword('')
      setNewPassword('')
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleSendPhoneVerification = async () => {
    try {
      const data = await api.post('/send-verification-phone', { phone: verifyPhone })
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  const handleVerifyPhone = async () => {
    try {
      const data = await api.post('/verify-phone', {
        phone: verifyPhone,
        code: verifyCode,
      })
      onResponse(data)
    } catch (e: any) {
      onResponse({ error: e.message })
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold">Profile</h2>
        <p className="text-sm text-muted-foreground">View and update your profile. Requires authentication.</p>
      </div>

      {/* Get Me */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Current User</CardTitle>
          <CardDescription>GET /me</CardDescription>
        </CardHeader>
        <CardContent>
          <Button onClick={handleGetMe}>Fetch Profile</Button>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Edit Profile */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Edit Profile</CardTitle>
            <CardDescription>PUT /profile</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="space-y-1">
              <Label htmlFor="p-name">Name</Label>
              <Input id="p-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="John Doe" />
            </div>
            <div className="space-y-1">
              <Label htmlFor="p-phone">Phone</Label>
              <Input id="p-phone" value={phone} onChange={(e) => setPhone(e.target.value)} placeholder="+1234567890" />
            </div>
            <div className="space-y-1">
              <Label htmlFor="p-avatar">Avatar URL</Label>
              <Input id="p-avatar" value={avatar} onChange={(e) => setAvatar(e.target.value)} placeholder="https://..." />
            </div>
            <Button onClick={handleUpdateProfile} className="w-full">Update Profile</Button>
          </CardContent>
        </Card>

        {/* Change Password */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Change Password</CardTitle>
            <CardDescription>PUT /change-password</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="space-y-1">
              <Label htmlFor="cp-old">Current Password</Label>
              <Input id="cp-old" type="password" value={oldPassword} onChange={(e) => setOldPassword(e.target.value)} />
            </div>
            <div className="space-y-1">
              <Label htmlFor="cp-new">New Password</Label>
              <Input id="cp-new" type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} />
            </div>
            <Button onClick={handleChangePassword} className="w-full">Change Password</Button>
          </CardContent>
        </Card>
      </div>

      {/* Phone Verification */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Phone Verification</CardTitle>
          <CardDescription>POST /send-verification-phone, POST /verify-phone</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex gap-4 items-end">
            <div className="space-y-1 flex-1">
              <Label htmlFor="vp-phone">Phone Number</Label>
              <Input id="vp-phone" value={verifyPhone} onChange={(e) => setVerifyPhone(e.target.value)} placeholder="+1234567890" />
            </div>
            <Button onClick={handleSendPhoneVerification} variant="outline">
              Send Code
            </Button>
          </div>
          <div className="flex gap-4 items-end">
            <div className="space-y-1 flex-1">
              <Label htmlFor="vp-code">Verification Code</Label>
              <Input id="vp-code" value={verifyCode} onChange={(e) => setVerifyCode(e.target.value)} placeholder="123456" />
            </div>
            <Button onClick={handleVerifyPhone} variant="outline">
              Verify
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
