import { defineConfig } from '@hey-api/openapi-ts';

// Input: the merged spec produced by clients/ts/scripts/merge-openapi.go.
// Regenerate via `make sdk` whenever a module openapi.yml changes.
//
// Plugin list is intentionally omitted — openapi-ts@0.53 emits the TS types
// and SDK by default, and each plugin object needs its own config sub-tree
// which surfaces as "Cannot read properties of undefined (reading 'output')"
// when supplied as bare strings.
export default defineConfig({
  input: './openapi.yml',
  output: {
    format: 'prettier',
    path: './src/generated',
  },
  client: '@hey-api/client-fetch',
});
