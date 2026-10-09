import js from '@eslint/js';
import { defineConfig, globalIgnores } from 'eslint/config';
import globals from 'globals';
import reactHooks from 'eslint-plugin-react-hooks';
import tseslint from 'typescript-eslint';

export default defineConfig(
	globalIgnores(['dist', 'website/dist', 'website/.astro']),
	{
		extends: [js.configs.recommended, tseslint.configs.strictTypeChecked],
		files: ['**/*.{ts,tsx}'],
		languageOptions: {
			ecmaVersion: 2020,
			globals: globals.browser,
			parserOptions: {
				projectService: true,
				tsconfigRootDir: import.meta.dirname
			}
		},
		rules: {
			/*
			 * Removing a key from a plain record in place is the operation here, not an accident of style:
			 * unknown request parameters, ungranted claims and unrecognised client metadata are stripped from
			 * the object the caller keeps using. The rule's alternative, a Map, would change every such caller.
			 */
			'@typescript-eslint/no-dynamic-delete': 'off',
			/*
			 * An async function with nothing to await is how an async contract is implemented here: the
			 * memory store beside the MongoDB and PostgreSQL ones, an addon default an override may make
			 * async. Dropping `async` would turn a synchronous throw into an exception the caller's
			 * `.catch()` or `allSettled` never sees. The real hazard, a promise left unawaited, is
			 * no-floating-promises', no-misused-promises' and await-thenable's.
			 */
			'@typescript-eslint/require-await': 'off',
			/*
			 * An async handler on a JSX attribute — onClick, onFinish, onConfirm — is the React idiom, and a
			 * click has nobody to await it. The hazard is a rejection no handler caught; the admin client
			 * reports every such rejection to the administrator (lib/admin/ui/adminClient.tsx), so the rule
			 * keeps every other void-return check and drops this one.
			 */
			'@typescript-eslint/no-misused-promises': [
				'error',
				{ checksVoidReturn: { attributes: false } }
			],
			/*
			 * `() => clearInterval(timer)` returns the void it was given, which reads as what it is. The rule
			 * stays for what it is for: a void value used inside an expression or returned as a value.
			 */
			'@typescript-eslint/no-confusing-void-expression': [
				'error',
				{ ignoreArrowShorthand: true }
			],
			/*
			 * A number or a boolean interpolates the same way String() would print it: counts, ports,
			 * lifetimes and status codes go into messages, and `enabled=${enabled}` names a test case. What
			 * stays refused is the value that prints as "undefined" or "[object Object]". The rule's options
			 * default to permissive, so the strict preset's other refusals are restated rather than inherited.
			 */
			'@typescript-eslint/restrict-template-expressions': [
				'error',
				{
					allowAny: false,
					allowBoolean: true,
					allowNever: false,
					allowNullish: false,
					allowNumber: true,
					allowRegExp: false
				}
			],
			/*
			 * A leading underscore marks a name unused on purpose. For a variable that is a type-level test:
			 * a constant whose assignment is the check and whose value nothing reads.
			 */
			'@typescript-eslint/no-unused-vars': [
				'error',
				{
					argsIgnorePattern: '^_',
					varsIgnorePattern: '^_',
					ignoreRestSiblings: true
				}
			]
		}
	},
	/*
	 * A spec hands a method to `expect(adapter.upsert).toHaveBeenCalled()` for its call record, and saves
	 * one only to assign it back after a stub; neither calls it without its object, which is the hazard
	 * the rule exists for. bun:test has no expect-aware variant of the rule, as Jest's plugin does. The
	 * rule stays on for lib/.
	 */
	{
		files: ['test/**/*.ts'],
		rules: {
			'@typescript-eslint/unbound-method': 'off'
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
