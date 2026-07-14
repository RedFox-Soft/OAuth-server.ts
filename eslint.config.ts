import js from '@eslint/js';
import { defineConfig, globalIgnores } from 'eslint/config';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default defineConfig(globalIgnores(['dist']), {
	extends: [js.configs.recommended, tseslint.configs.strict],
	files: ['**/*.{ts,tsx}'],
	languageOptions: {
		ecmaVersion: 2020,
		globals: globals.browser
	},
	rules: {
		'@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }]
	}
});
