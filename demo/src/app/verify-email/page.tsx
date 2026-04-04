'use client'

import { useSearchParams } from 'next/navigation'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'

export default function VerifyEmailPage() {
  const searchParams = useSearchParams()
  const status = searchParams.get('status')
  const message = searchParams.get('message')

  const success = status === 'success'

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>Email Verification</CardTitle>
        </CardHeader>
        <CardContent>
          {success ? (
            <div>
              <p className="text-green-600 mb-4">{message || 'Email verified successfully.'}</p>
              <a href="/" className="text-blue-600 underline">Go to login</a>
            </div>
          ) : (
            <div>
              <p className="text-red-600 mb-4">{message || 'Email verification failed.'}</p>
              <a href="/" className="text-blue-600 underline">Go back</a>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
