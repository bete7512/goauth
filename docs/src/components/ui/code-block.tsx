"use client";

import React, { useState } from 'react';
import { Copy, Check } from 'lucide-react';
import { Button } from './button';
import { cn } from '@/lib/utils';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';

interface CodeBlockProps {
  children: string;
  language?: string;
  title?: string;
  className?: string;
  showLineNumbers?: boolean;
}

export const CodeBlock = ({ 
  children, 
  language = 'go',
  title,
  className,
  showLineNumbers = false
}: CodeBlockProps) => {
  const [copied, setCopied] = useState(false);

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(children);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  const getLanguageColor = (lang: string) => {
    const colors: Record<string, string> = {
      go: 'bg-blue-500/10 text-blue-500 border-blue-500/20',
      bash: 'bg-green-500/10 text-green-500 border-green-500/20',
      json: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
      typescript: 'bg-blue-600/10 text-blue-600 border-blue-600/20',
      javascript: 'bg-yellow-600/10 text-yellow-600 border-yellow-600/20',
      html: 'bg-orange-500/10 text-orange-500 border-orange-500/20',
      css: 'bg-purple-500/10 text-purple-500 border-purple-500/20',
      sql: 'bg-indigo-500/10 text-indigo-500 border-indigo-500/20',
      yaml: 'bg-red-500/10 text-red-500 border-red-500/20',
      text: 'bg-gray-500/10 text-gray-500 border-gray-500/20',
    };
    return colors[lang] || colors.text;
  };

  return (
    <div className={cn("relative group", className)}>
      {/* Header */}
      <div className="flex items-center justify-between bg-gradient-to-r from-gray-900 to-gray-800 px-4 py-3 rounded-t-lg border border-gray-700">
        <div className="flex items-center space-x-2">
          {title && (
            <span className="text-sm font-medium text-gray-300">{title}</span>
          )}
          {language && (
            <span className={cn(
              "px-2 py-1 text-xs font-medium rounded border",
              getLanguageColor(language)
            )}>
              {language.toUpperCase()}
            </span>
          )}
        </div>
        <Button
          variant="ghost"
          size="sm"
          onClick={copyToClipboard}
          className="h-8 w-8 p-0 hover:bg-gray-700/50 text-gray-400 hover:text-gray-200"
        >
          {copied ? (
            <Check className="h-4 w-4 text-green-400" />
          ) : (
            <Copy className="h-4 w-4" />
          )}
        </Button>
      </div>

      {/* Code Content */}
      <div className="bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 rounded-b-lg border border-gray-700 overflow-hidden">
        <SyntaxHighlighter
          language={language}
          style={vscDarkPlus}
          showLineNumbers={showLineNumbers}
          customStyle={{
            margin: 0,
            padding: '1rem',
            background: 'transparent',
            fontSize: '14px',
            lineHeight: '1.6',
            fontFamily: 'ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, Monaco, "Fira Code", "Cascadia Code", "Roboto Mono", monospace',
          }}
          lineNumberStyle={{
            color: '#858585',
            fontSize: '12px',
            paddingRight: '1rem',
            minWidth: '3em',
          }}
        >
          {children}
        </SyntaxHighlighter>
      </div>

      {/* Gradient Overlay */}
      <div className="absolute inset-0 pointer-events-none bg-gradient-to-r from-transparent via-transparent to-gray-900/5 rounded-lg" />
    </div>
  );
};

// Enhanced code block with line numbers
export const CodeBlockWithLines = ({ 
  children, 
  language = 'go',
  title,
  className 
}: CodeBlockProps) => {
  return (
    <CodeBlock
      children={children}
      language={language}
      title={title}
      className={className}
      showLineNumbers={true}
    />
  );
}; 