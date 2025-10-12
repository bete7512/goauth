'use client'

import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { SignupForm } from '@/components/core/signup-form'
import { LoginForm } from '@/components/core/login-form'
import { ForgotPasswordForm } from '@/components/core/forgot-password-form'
import { AvailabilityChecker } from '@/components/core/availability-checker'
import { ApiConfigPanel } from '@/components/api-config-panel'
import { apiClient } from '@/lib/api-config'
import type { AuthResponse, MessageResponse, CheckAvailabilityResponse } from '@/types/core'

type ActiveTab = 'signup' | 'login' | 'forgot-password' | 'availability'

export default function DemoPage() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('signup')
  const [user, setUser] = useState<any>(null)
  const [message, setMessage] = useState<string>('')
  const [currentApiUrl, setCurrentApiUrl] = useState<string>('http://localhost:8080/api/v1')

  const handleAuthSuccess = (response: AuthResponse) => {
    setUser(response.user)
    setMessage(`Welcome ${response.user.first_name || response.user.email}!`)
    
    // Store token in localStorage for demo purposes
    if (response.token) {
      localStorage.setItem('auth_token', response.token)
    }
  }

  const handleAuthError = (error: string) => {
    setMessage(`Error: ${error}`)
  }

  const handleMessageSuccess = (response: MessageResponse) => {
    setMessage(response.message)
  }

  const handleAvailabilityResult = (result: CheckAvailabilityResponse) => {
    setMessage(`${result.field} is ${result.available ? 'available' : 'not available'}`)
  }

  const handleLogout = () => {
    localStorage.removeItem('auth_token')
    setUser(null)
    setMessage('Logged out successfully')
  }

  const handleApiConfigChange = (baseUrl: string, basePath: string) => {
    const fullUrl = `${baseUrl}${basePath}`
    setCurrentApiUrl(fullUrl)
    apiClient.updateConfig({ baseUrl, basePath })
  }

  const tabs = [
    { id: 'signup' as ActiveTab, label: 'Sign Up', description: 'Create a new account', icon: '🚀' },
    { id: 'login' as ActiveTab, label: 'Sign In', description: 'Access your account', icon: '🔐' },
    { id: 'forgot-password' as ActiveTab, label: 'Reset Password', description: 'Recover your password', icon: '🔑' },
    { id: 'availability' as ActiveTab, label: 'Check Availability', description: 'Verify field availability', icon: '✅' },
  ]

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 relative overflow-hidden">
      {/* API Configuration Panel */}
      <ApiConfigPanel onConfigChange={handleApiConfigChange} />
      
      {/* Animated Background */}
      <div className="absolute inset-0 opacity-20">
        <div className="absolute inset-0 bg-gradient-to-r from-purple-500/10 to-pink-500/10"></div>
      </div>
      
      {/* Floating Orbs */}
      <div className="absolute top-20 left-20 w-72 h-72 bg-purple-500 rounded-full mix-blend-multiply filter blur-xl opacity-20 animate-pulse"></div>
      <div className="absolute top-40 right-20 w-72 h-72 bg-yellow-500 rounded-full mix-blend-multiply filter blur-xl opacity-20 animate-pulse animation-delay-2000"></div>
      <div className="absolute -bottom-8 left-40 w-72 h-72 bg-pink-500 rounded-full mix-blend-multiply filter blur-xl opacity-20 animate-pulse animation-delay-4000"></div>

      <div className="container mx-auto px-4 relative z-10">
        {/* Header */}
        <div className="text-center mb-12 pt-8">
          <div className="inline-flex items-center justify-center w-20 h-20 bg-gradient-to-r from-purple-500 to-pink-500 rounded-full mb-6 animate-bounce">
            <span className="text-3xl">🔐</span>
          </div>
          <h1 className="text-6xl font-bold bg-gradient-to-r from-white via-purple-200 to-pink-200 bg-clip-text text-transparent mb-4 animate-fade-in">
            Go-Auth Demo
          </h1>
          <p className="text-xl text-gray-300 mb-6 animate-fade-in-delay">
            Experience the future of authentication
          </p>
          <div className="inline-flex items-center space-x-2 bg-black/20 backdrop-blur-sm border border-white/20 rounded-full px-6 py-3 animate-fade-in-delay-2">
            <div className="w-3 h-3 bg-green-400 rounded-full animate-pulse"></div>
            <span className="text-sm text-gray-300">API Endpoint:</span>
            <code className="bg-purple-900/50 text-purple-200 px-3 py-1 rounded-lg text-sm font-mono">{currentApiUrl}</code>
          </div>
        </div>

        {/* User Status */}
        {user && (
          <div className="max-w-md mx-auto mb-8 animate-slide-down">
            <Card className="bg-gradient-to-r from-green-500/10 to-emerald-500/10 border-green-500/20 backdrop-blur-sm">
              <CardHeader className="text-center">
                <div className="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-r from-green-400 to-emerald-500 rounded-full mb-4 mx-auto">
                  <span className="text-2xl">👤</span>
                </div>
                <CardTitle className="text-green-400 text-xl">Welcome Back!</CardTitle>
                <CardDescription className="text-gray-300">
                  You're successfully authenticated
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 gap-3">
                  <div className="flex items-center space-x-3 p-3 bg-black/20 rounded-lg">
                    <span className="text-lg">👤</span>
                    <div>
                      <p className="text-sm text-gray-400">Name</p>
                      <p className="text-white font-medium">{user.first_name} {user.last_name}</p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-3 p-3 bg-black/20 rounded-lg">
                    <span className="text-lg">📧</span>
                    <div>
                      <p className="text-sm text-gray-400">Email</p>
                      <p className="text-white font-medium">{user.email}</p>
                    </div>
                  </div>
                  {user.username && (
                    <div className="flex items-center space-x-3 p-3 bg-black/20 rounded-lg">
                      <span className="text-lg">🏷️</span>
                      <div>
                        <p className="text-sm text-gray-400">Username</p>
                        <p className="text-white font-medium">{user.username}</p>
                      </div>
                    </div>
                  )}
                  {user.phone_number && (
                    <div className="flex items-center space-x-3 p-3 bg-black/20 rounded-lg">
                      <span className="text-lg">📱</span>
                      <div>
                        <p className="text-sm text-gray-400">Phone</p>
                        <p className="text-white font-medium">{user.phone_number}</p>
                      </div>
                    </div>
                  )}
                  <div className="flex items-center space-x-3 p-3 bg-black/20 rounded-lg">
                    <span className="text-lg">✅</span>
                    <div>
                      <p className="text-sm text-gray-400">Status</p>
                      <div className="flex space-x-4">
                        <span className={`text-xs px-2 py-1 rounded-full ${user.email_verified ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
                          Email {user.email_verified ? 'Verified' : 'Pending'}
                        </span>
                        <span className={`text-xs px-2 py-1 rounded-full ${user.phone_number_verified ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
                          Phone {user.phone_number_verified ? 'Verified' : 'Pending'}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
                <Button 
                  onClick={handleLogout} 
                  className="w-full bg-gradient-to-r from-red-500 to-pink-500 hover:from-red-600 hover:to-pink-600 text-white border-0"
                >
                  🚪 Logout
                </Button>
              </CardContent>
            </Card>
          </div>
        )}

        {/* Message Display */}
        {message && (
          <div className="max-w-md mx-auto mb-8 animate-slide-down">
            <div className={`p-4 rounded-xl backdrop-blur-sm border ${
              message.startsWith('Error:') 
                ? 'bg-red-500/10 border-red-500/20 text-red-300' 
                : 'bg-green-500/10 border-green-500/20 text-green-300'
            }`}>
              <div className="flex items-center space-x-3">
                <div className={`w-8 h-8 rounded-full flex items-center justify-center ${
                  message.startsWith('Error:') ? 'bg-red-500/20' : 'bg-green-500/20'
                }`}>
                  {message.startsWith('Error:') ? '❌' : '✅'}
                </div>
                <p className="text-sm font-medium">{message}</p>
              </div>
            </div>
          </div>
        )}

        {/* Tab Navigation */}
        <div className="max-w-6xl mx-auto mb-8">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => {
                  setActiveTab(tab.id)
                  setMessage('')
                }}
                className={`group relative p-6 rounded-xl transition-all duration-300 ${
                  activeTab === tab.id
                    ? 'bg-gradient-to-r from-purple-500/20 to-pink-500/20 border-2 border-purple-400/50 shadow-lg shadow-purple-500/25'
                    : 'bg-black/20 border border-white/10 hover:bg-white/5 hover:border-white/20'
                }`}
              >
                <div className="text-center">
                  <div className={`text-3xl mb-3 transition-transform duration-300 ${
                    activeTab === tab.id ? 'scale-110' : 'group-hover:scale-105'
                  }`}>
                    {tab.icon}
                  </div>
                  <h3 className={`font-semibold mb-1 ${
                    activeTab === tab.id ? 'text-white' : 'text-gray-300'
                  }`}>
                    {tab.label}
                  </h3>
                  <p className={`text-xs ${
                    activeTab === tab.id ? 'text-purple-200' : 'text-gray-400'
                  }`}>
                    {tab.description}
                  </p>
                </div>
                {activeTab === tab.id && (
                  <div className="absolute inset-0 rounded-xl bg-gradient-to-r from-purple-500/10 to-pink-500/10 animate-pulse"></div>
                )}
              </button>
            ))}
          </div>
        </div>

        {/* Tab Content */}
        <div className="max-w-6xl mx-auto">
          <div className="animate-fade-in">
            {activeTab === 'signup' && (
              <SignupForm onSuccess={handleAuthSuccess} onError={handleAuthError} />
            )}
            
            {activeTab === 'login' && (
              <LoginForm onSuccess={handleAuthSuccess} onError={handleAuthError} />
            )}
            
            {activeTab === 'forgot-password' && (
              <ForgotPasswordForm onSuccess={handleMessageSuccess} onError={handleAuthError} />
            )}
            
            {activeTab === 'availability' && (
              <div className="space-y-8">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  <AvailabilityChecker 
                    field="email" 
                    onResult={handleAvailabilityResult}
                  />
                  <AvailabilityChecker 
                    field="username" 
                    onResult={handleAvailabilityResult}
                  />
                  <AvailabilityChecker 
                    field="phone" 
                    onResult={handleAvailabilityResult}
                  />
                </div>
              </div>
            )}
          </div>
        </div>

        {/* API Information */}
        <div className="max-w-6xl mx-auto mt-16 pb-16">
          <Card className="bg-black/20 border-white/10 backdrop-blur-sm">
            <CardHeader className="text-center">
              <CardTitle className="text-2xl bg-gradient-to-r from-purple-400 to-pink-400 bg-clip-text text-transparent">
                🚀 API Configuration
              </CardTitle>
              <CardDescription className="text-gray-300">
                Complete Go-Auth API endpoints reference
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-6">
                <div>
                  <h4 className="font-semibold mb-4 text-purple-300 flex items-center">
                    <span className="mr-2">🔐</span>
                    Core Module Endpoints
                  </h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                    <div className="p-3 bg-purple-500/10 rounded-lg border border-purple-500/20">
                      <code className="text-purple-300 text-sm">POST /signup</code>
                      <p className="text-gray-400 text-xs mt-1">User registration</p>
                    </div>
                    <div className="p-3 bg-blue-500/10 rounded-lg border border-blue-500/20">
                      <code className="text-blue-300 text-sm">POST /login</code>
                      <p className="text-gray-400 text-xs mt-1">User authentication</p>
                    </div>
                    <div className="p-3 bg-red-500/10 rounded-lg border border-red-500/20">
                      <code className="text-red-300 text-sm">POST /logout</code>
                      <p className="text-gray-400 text-xs mt-1">User logout</p>
                    </div>
                    <div className="p-3 bg-green-500/10 rounded-lg border border-green-500/20">
                      <code className="text-green-300 text-sm">GET /me</code>
                      <p className="text-gray-400 text-xs mt-1">Get current user</p>
                    </div>
                    <div className="p-3 bg-yellow-500/10 rounded-lg border border-yellow-500/20">
                      <code className="text-yellow-300 text-sm">GET /profile</code>
                      <p className="text-gray-400 text-xs mt-1">Get user profile</p>
                    </div>
                    <div className="p-3 bg-indigo-500/10 rounded-lg border border-indigo-500/20">
                      <code className="text-indigo-300 text-sm">PUT /profile</code>
                      <p className="text-gray-400 text-xs mt-1">Update user profile</p>
                    </div>
                    <div className="p-3 bg-pink-500/10 rounded-lg border border-pink-500/20">
                      <code className="text-pink-300 text-sm">PUT /change-password</code>
                      <p className="text-gray-400 text-xs mt-1">Change password</p>
                    </div>
                    <div className="p-3 bg-orange-500/10 rounded-lg border border-orange-500/20">
                      <code className="text-orange-300 text-sm">POST /forgot-password</code>
                      <p className="text-gray-400 text-xs mt-1">Request password reset</p>
                    </div>
                    <div className="p-3 bg-teal-500/10 rounded-lg border border-teal-500/20">
                      <code className="text-teal-300 text-sm">POST /reset-password</code>
                      <p className="text-gray-400 text-xs mt-1">Reset password</p>
                    </div>
                    <div className="p-3 bg-cyan-500/10 rounded-lg border border-cyan-500/20">
                      <code className="text-cyan-300 text-sm">POST /send-verification-email</code>
                      <p className="text-gray-400 text-xs mt-1">Send email verification</p>
                    </div>
                    <div className="p-3 bg-emerald-500/10 rounded-lg border border-emerald-500/20">
                      <code className="text-emerald-300 text-sm">POST /verify-email</code>
                      <p className="text-gray-400 text-xs mt-1">Verify email</p>
                    </div>
                    <div className="p-3 bg-violet-500/10 rounded-lg border border-violet-500/20">
                      <code className="text-violet-300 text-sm">POST /send-verification-phone</code>
                      <p className="text-gray-400 text-xs mt-1">Send phone verification</p>
                    </div>
                    <div className="p-3 bg-rose-500/10 rounded-lg border border-rose-500/20">
                      <code className="text-rose-300 text-sm">POST /verify-phone</code>
                      <p className="text-gray-400 text-xs mt-1">Verify phone</p>
                    </div>
                    <div className="p-3 bg-lime-500/10 rounded-lg border border-lime-500/20">
                      <code className="text-lime-300 text-sm">POST /availability/email</code>
                      <p className="text-gray-400 text-xs mt-1">Check email availability</p>
                    </div>
                    <div className="p-3 bg-sky-500/10 rounded-lg border border-sky-500/20">
                      <code className="text-sky-300 text-sm">POST /availability/username</code>
                      <p className="text-gray-400 text-xs mt-1">Check username availability</p>
                    </div>
                    <div className="p-3 bg-amber-500/10 rounded-lg border border-amber-500/20">
                      <code className="text-amber-300 text-sm">POST /availability/phone</code>
                      <p className="text-gray-400 text-xs mt-1">Check phone availability</p>
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}
