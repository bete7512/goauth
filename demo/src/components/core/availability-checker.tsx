'use client'

import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { coreApiService } from '@/services/core-api'
import type { CheckAvailabilityRequest, CheckAvailabilityResponse } from '@/types/core'

interface AvailabilityCheckerProps {
  field: 'email' | 'username' | 'phone'
  onResult?: (result: CheckAvailabilityResponse) => void
}

export function AvailabilityChecker({ field, onResult }: AvailabilityCheckerProps) {
  const [value, setValue] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<CheckAvailabilityResponse | null>(null)
  const [error, setError] = useState<string>('')

  const validateInput = (): boolean => {
    if (!value.trim()) {
      setError(`${field} is required`)
      return false
    }

    switch (field) {
      case 'email':
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
          setError('Invalid email format')
          return false
        }
        break
      case 'username':
        if (!/^[a-zA-Z0-9_-]{3,30}$/.test(value)) {
          setError('Username must be 3-30 characters and contain only letters, numbers, underscores, and hyphens')
          return false
        }
        break
      case 'phone':
        if (!/^\+[1-9]\d{1,14}$/.test(value)) {
          setError('Invalid phone number format (use E.164 format: +1234567890)')
          return false
        }
        break
    }

    setError('')
    return true
  }

  const checkAvailability = async () => {
    if (!validateInput()) {
      return
    }

    setLoading(true)
    try {
      const request: CheckAvailabilityRequest = { [field]: value }
      
      let response: CheckAvailabilityResponse
      switch (field) {
        case 'email':
          response = await coreApiService.checkEmailAvailability(request)
          break
        case 'username':
          response = await coreApiService.checkUsernameAvailability(request)
          break
        case 'phone':
          response = await coreApiService.checkPhoneAvailability(request)
          break
      }
      
      setResult(response)
      onResult?.(response)
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Check failed'
      setError(errorMessage)
    } finally {
      setLoading(false)
    }
  }

  const getFieldLabel = () => {
    switch (field) {
      case 'email': return 'Email Address'
      case 'username': return 'Username'
      case 'phone': return 'Phone Number'
    }
  }

  const getFieldPlaceholder = () => {
    switch (field) {
      case 'email': return 'john@example.com'
      case 'username': return 'johndoe'
      case 'phone': return '+1234567890'
    }
  }

  return (
    <Card className="w-full bg-black/20 border-white/10 backdrop-blur-sm">
      <CardHeader className="text-center">
        <div className="inline-flex items-center justify-center w-12 h-12 bg-gradient-to-r from-teal-500 to-cyan-500 rounded-full mb-3 mx-auto">
          <span className="text-lg">✅</span>
        </div>
        <CardTitle className="text-lg bg-gradient-to-r from-teal-400 to-cyan-400 bg-clip-text text-transparent">Check {getFieldLabel()} Availability</CardTitle>
        <CardDescription className="text-gray-300 text-sm">
          Verify if your {field} is available
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          <div>
            <Label htmlFor={field}>{getFieldLabel()}</Label>
            <div className="flex space-x-2">
              <Input
                id={field}
                type={field === 'phone' ? 'tel' : field === 'email' ? 'email' : 'text'}
                value={value}
                onChange={(e) => {
                  setValue(e.target.value)
                  setError('')
                  setResult(null)
                }}
                placeholder={getFieldPlaceholder()}
                className={error ? 'border-red-500' : ''}
              />
              <Button 
                onClick={checkAvailability} 
                disabled={loading || !value.trim()}
                className="bg-gradient-to-r from-teal-500 to-cyan-500 hover:from-teal-600 hover:to-cyan-600 text-white border-0"
              >
                {loading ? '🔍 Checking...' : '🔍 Check'}
              </Button>
            </div>
            {error && <p className="text-sm text-red-500 mt-1">{error}</p>}
          </div>

          {result && (
            <div className={`p-3 rounded-md ${
              result.available 
                ? 'bg-green-50 border border-green-200 text-green-800' 
                : 'bg-red-50 border border-red-200 text-red-800'
            }`}>
              <div className="flex items-center space-x-2">
                {result.available ? (
                  <svg className="h-5 w-5" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                  </svg>
                ) : (
                  <svg className="h-5 w-5" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                  </svg>
                )}
                <span className="font-medium">
                  {result.available ? 'Available' : 'Not Available'}
                </span>
              </div>
              {result.message && (
                <p className="text-sm mt-1">{result.message}</p>
              )}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  )
}
