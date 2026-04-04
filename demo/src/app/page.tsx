'use client'

import { useState, useEffect } from 'react'
import { Button } from '@/components/ui/button'
import { api } from '@/lib/api-client'
import type { User, OrgInfo } from '@/types'

import { SettingsSection } from '@/components/sections/settings-section'
import { AuthSection } from '@/components/sections/auth-section'
import { ProfileSection } from '@/components/sections/profile-section'
import { SessionsSection } from '@/components/sections/sessions-section'
import { AdminSection } from '@/components/sections/admin-section'
import { AuditSection } from '@/components/sections/audit-section'
import { OrgSection } from '@/components/sections/org-section'
import { TwoFactorSection } from '@/components/sections/twofactor-section'
import { MagicLinkSection } from '@/components/sections/magiclink-section'

type Section = 'settings' | 'auth' | 'profile' | 'sessions' | 'admin' | 'audit' | 'orgs' | '2fa' | 'magiclink'

const sidebarItems: { id: Section; label: string; requiresAuth: boolean }[] = [
  { id: 'settings', label: 'Settings', requiresAuth: false },
  { id: 'auth', label: 'Auth', requiresAuth: false },
  { id: 'profile', label: 'Profile', requiresAuth: true },
  { id: 'sessions', label: 'Sessions', requiresAuth: true },
  { id: 'admin', label: 'Admin', requiresAuth: true },
  { id: 'audit', label: 'Audit', requiresAuth: true },
  { id: 'orgs', label: 'Organizations', requiresAuth: true },
  { id: '2fa', label: '2FA', requiresAuth: true },
  { id: 'magiclink', label: 'Magic Link', requiresAuth: false },
]

export default function DemoPage() {
  const [activeSection, setActiveSection] = useState<Section>('auth')
  const [user, setUser] = useState<User | null>(null)
  const [token, setToken] = useState<string | null>(null)
  const [organizations, setOrganizations] = useState<OrgInfo[]>([])
  const [activeOrg, setActiveOrg] = useState<OrgInfo | null>(null)
  const [response, setResponse] = useState<unknown>(null)
  const [tempToken2FA, setTempToken2FA] = useState<string>('')

  // Restore token on mount
  useEffect(() => {
    const saved = api.getToken()
    if (saved) {
      setToken(saved)
      api.get<User>('/me').then((u) => {
        setUser(u)
      }).catch(() => {
        api.setToken(null)
        setToken(null)
      })
    }
  }, [])

  const handleLogin = (u: User, t: string, orgs: OrgInfo[]) => {
    setUser(u)
    setToken(t)
    setOrganizations(orgs)
    if (orgs.length > 0) setActiveOrg(orgs[0])
  }

  const handleLogout = async () => {
    try {
      await api.post('/logout')
    } catch {
      // Ignore logout errors
    }
    api.clearTokens()
    setUser(null)
    setToken(null)
    setOrganizations([])
    setActiveOrg(null)
    setResponse({ message: 'Logged out' })
    setActiveSection('auth')
  }

  const handleResponse = (data: unknown) => {
    setResponse(data)
  }

  return (
    <div className="flex h-screen">
      {/* Sidebar */}
      <aside className="w-56 border-r bg-white flex flex-col shrink-0">
        <div className="p-4 border-b">
          <h1 className="font-semibold text-base">GoAuth Demo</h1>
          <p className="text-xs text-muted-foreground mt-0.5">Testing UI</p>
        </div>

        {user && token && (
          <div className="p-3 border-b bg-gray-50">
            <p className="text-sm font-medium truncate">{user.name || user.email}</p>
            <p className="text-xs text-muted-foreground truncate">{user.email}</p>
            <Button onClick={handleLogout} variant="outline" size="sm" className="mt-2 w-full text-xs">
              Logout
            </Button>
          </div>
        )}

        <nav className="flex-1 py-2 overflow-y-auto">
          {sidebarItems.map((s) => (
            <button
              key={s.id}
              onClick={() => setActiveSection(s.id)}
              className={`w-full text-left px-4 py-2 text-sm transition-colors ${
                activeSection === s.id
                  ? 'bg-gray-100 font-medium text-foreground'
                  : 'text-muted-foreground hover:bg-gray-50 hover:text-foreground'
              }`}
            >
              {s.label}
              {s.requiresAuth && !token && (
                <span className="ml-1 text-xs text-muted-foreground">(auth)</span>
              )}
            </button>
          ))}
        </nav>

        <div className="p-3 border-t text-xs text-muted-foreground">
          <code className="block truncate">{api.baseUrl}</code>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 flex flex-col overflow-hidden">
        <div className="flex-1 overflow-y-auto p-6">
          {activeSection === 'settings' && (
            <SettingsSection onResponse={handleResponse} />
          )}
          {activeSection === 'auth' && (
            <AuthSection
              onLogin={handleLogin}
              onResponse={handleResponse}
              onChallenge={(tempToken) => {
                setTempToken2FA(tempToken)
                setActiveSection('2fa')
              }}
            />
          )}
          {activeSection === 'profile' && (
            <ProfileSection onResponse={handleResponse} />
          )}
          {activeSection === 'sessions' && (
            <SessionsSection onResponse={handleResponse} />
          )}
          {activeSection === 'admin' && (
            <AdminSection onResponse={handleResponse} />
          )}
          {activeSection === 'audit' && (
            <AuditSection onResponse={handleResponse} />
          )}
          {activeSection === 'orgs' && (
            <OrgSection
              organizations={organizations}
              activeOrg={activeOrg}
              onOrgSwitch={setActiveOrg}
              onOrgsUpdate={setOrganizations}
              onResponse={handleResponse}
            />
          )}
          {activeSection === '2fa' && (
            <TwoFactorSection
              onResponse={handleResponse}
              tempToken={tempToken2FA}
              onLoginSuccess={(data) => {
                if (data.user) {
                  setUser(data.user)
                  setToken(data.access_token)
                }
                setTempToken2FA('')
              }}
            />
          )}
          {activeSection === 'magiclink' && (
            <MagicLinkSection onLogin={handleLogin} onResponse={handleResponse} />
          )}
        </div>

        {/* Response viewer */}
        <div className="border-t bg-white shrink-0">
          <div className="flex items-center justify-between px-4 py-2 border-b">
            <span className="text-xs font-medium text-muted-foreground">Response</span>
            {response !== null && (
              <Button
                variant="ghost"
                size="sm"
                className="text-xs h-6"
                onClick={() => setResponse(null)}
              >
                Clear
              </Button>
            )}
          </div>
          <pre className="p-4 text-xs font-mono overflow-auto max-h-64 bg-gray-50 text-gray-800">
            {response ? JSON.stringify(response, null, 2) : 'No response yet. Make an API call to see results here.'}
          </pre>
        </div>
      </main>
    </div>
  )
}
