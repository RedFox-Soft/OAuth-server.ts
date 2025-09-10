import js from '@eslint/js';
import globals from 'globals';
import tseslint from 'typescript-eslint';
import { flatConfigs } from 'eslint-plugin-import';

export default tseslint.config(
	{ ignores: ['dist'] },
	{
		extends: [
			js.configs.recommended,
			flatConfigs.recommended,
			tseslint.configs.strict
		],
		files: ['**/*.{ts,tsx}'],
		languageOptions: {
			ecmaVersion: 2020,
			globals: globals.browser
		},
		rules: {
			'import/no-unresolved': 'off',
			'@typescript-eslint/no-unused-vars': [
				'error',
				{ argsIgnorePattern: '^_' }
			]
		}
	}
);
