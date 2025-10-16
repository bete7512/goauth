'use client'

import { useState, useEffect } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'

interface ApiConfigPanelProps {
  onConfigChange: (baseUrl: string, basePath: string) => void
}

export function ApiConfigPanel({ onConfigChange }: ApiConfigPanelProps) {
  const [baseUrl, setBaseUrl] = useState('http://localhost:8080')
  const [basePath, setBasePath] = useState('/api/v1')
  const [isOpen, setIsOpen] = useState(false)

  useEffect(() => {
    // Load saved config from localStorage
    const savedBaseUrl = localStorage.getItem('demo_api_base_url') || 'http://localhost:8080'
    const savedBasePath = localStorage.getItem('demo_api_base_path') || '/api/v1'
    
    setBaseUrl(savedBaseUrl)
    setBasePath(savedBasePath)
    onConfigChange(savedBaseUrl, savedBasePath)
  }, [onConfigChange])

  const handleSave = () => {
    localStorage.setItem('demo_api_base_url', baseUrl)
    localStorage.setItem('demo_api_base_path', basePath)
    onConfigChange(baseUrl, basePath)
    setIsOpen(false)
  }

  const handleReset = () => {
    setBaseUrl('http://localhost:8080')
    setBasePath('/api/v1')
  }

  const fullUrl = `${baseUrl}${basePath}`

  return (
    <div className="fixed top-4 right-4 z-50">
      <Button
        onClick={() => setIsOpen(!isOpen)}
        className="bg-black/20 border border-white/20 backdrop-blur-sm hover:bg-white/10"
        variant="outline"
      >
        ⚙️ API Config
      </Button>

      {isOpen && (
        <Card className="absolute top-12 right-0 w-80 bg-black/20 border-white/20 backdrop-blur-sm">
          <CardHeader>
            <CardTitle className="text-lg bg-gradient-to-r from-blue-400 to-cyan-400 bg-clip-text text-transparent">
              🔧 API Configuration
            </CardTitle>
            <CardDescription className="text-gray-300">
              Configure your Go-Auth server endpoint
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label htmlFor="baseUrl">Base URL</Label>
              <Input
                id="baseUrl"
                type="text"
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
                placeholder="http://localhost:8080"
                className="bg-black/20 border-white/20 text-white"
              />
              <p className="text-xs text-gray-400 mt-1">
                Server host and port (e.g., http://localhost:8080, https://api.example.com)
              </p>
            </div>

            <div>
              <Label htmlFor="basePath">Base Path</Label>
              <Input
                id="basePath"
                type="text"
                value={basePath}
                onChange={(e) => setBasePath(e.target.value)}
                placeholder="/api/v1"
                className="bg-black/20 border-white/20 text-white"
              />
              <p className="text-xs text-gray-400 mt-1">
                API path prefix (e.g., /api/v1, /auth, /v2)
              </p>
            </div>

            <div className="p-3 bg-blue-500/10 border border-blue-500/20 rounded-lg">
              <p className="text-xs text-blue-300 font-medium">Current Endpoint:</p>
              <code className="text-blue-200 text-sm break-all">{fullUrl}</code>
            </div>

            <div className="flex space-x-2">
              <Button
                onClick={handleSave}
                className="flex-1 bg-gradient-to-r from-green-500 to-emerald-500 hover:from-green-600 hover:to-emerald-600 text-white border-0"
              >
                💾 Save
              </Button>
              <Button
                onClick={handleReset}
                variant="outline"
                className="flex-1 border-white/20 text-white hover:bg-white/10"
              >
                🔄 Reset
              </Button>
            </div>

            <div className="text-xs text-gray-400 space-y-1">
              <p><strong>Examples:</strong></p>
              <p>• Local: <code>http://localhost:8080</code></p>
              <p>• Production: <code>https://api.yourdomain.com</code></p>
              <p>• Docker: <code>http://localhost:3000</code></p>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}






