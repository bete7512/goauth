import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'Go-Auth Demo',
  description: 'Interactive demo of the Go-Auth authentication system',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}
