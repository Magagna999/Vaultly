import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import reactHooks from 'eslint-plugin-react-hooks';
import globals from 'globals';

export default tseslint.config(
  { ignores: ['dist', 'node_modules', '.tasks'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['**/*.{ts,tsx}'],
    languageOptions: { globals: { ...globals.browser, ...globals.node, chrome: 'readonly' } },
    plugins: { 'react-hooks': reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      // Credentials must never reach the console: only src/utils/logger.ts may log.
      'no-console': 'error',
      '@typescript-eslint/no-explicit-any': 'error',
    },
  },
  { files: ['src/utils/logger.ts'], rules: { 'no-console': 'off' } },
);
