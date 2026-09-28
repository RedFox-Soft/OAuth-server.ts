import js from '@eslint/js';
import { defineConfig, globalIgnores } from 'eslint/config';
import globals from 'globals';
import reactHooks from 'eslint-plugin-react-hooks';
import tseslint from 'typescript-eslint';

export default defineConfig(
	globalIgnores(['dist', 'website/dist', 'website/.astro']),
	{
		extends: [js.configs.recommended, tseslint.configs.strict],
		files: ['**/*.{ts,tsx}'],
		languageOptions: {
			ecmaVersion: 2020,
			globals: globals.browser
		},
		rules: {
			/*
			 * Removing a key from a plain record in place is the operation here, not an accident of style:
			 * unknown request parameters, ungranted claims and unrecognised client metadata are stripped from
			 * the object the caller keeps using. The rule's alternative, a Map, would change every such caller.
			 */
			'@typescript-eslint/no-dynamic-delete': 'off',
			'@typescript-eslint/no-unused-vars': [
				'error',
				{ argsIgnorePattern: '^_', ignoreRestSiblings: true }
			]
		}
	},
	/*
	 * Only the .tsx files are React. The server's addon accessors are also named use*
	 * (`useGrantedResource`), and the hook rules would read them as hooks called outside a component.
	 */
	{
		extends: [reactHooks.configs.flat.recommended],
		files: ['**/*.tsx']
	}
);
