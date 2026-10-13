import { Alert, Button, Input, Space, Typography } from 'antd';
import { DeleteOutlined } from '@ant-design/icons';
import { isStandardOidcScope } from '../../../consts/oidc_scopes.js';
import type { Values } from './model.js';

/*
 * What each of the instance's own scopes lets an application do, as the consent page says it.
 *
 * A row per defined custom scope rather than a JSON field, because the set of keys the server accepts is
 * exactly the scopes defined under Supported scopes and Claims, minus the standard ones — something the
 * page can list and a textarea would leave the operator to get wrong and learn about from a 422.
 * Descriptions of scopes no longer defined are kept on screen with a way to remove them: saving with one
 * left in is refused, and the operator needs to see which.
 */

function definedCustomScopes(values: Values): string[] {
	const scopes = new Set<string>();
	const listed = values['scopes'];
	if (Array.isArray(listed)) {
		for (const scope of listed)
			if (typeof scope === 'string') scopes.add(scope);
	}
	const claims = values['claims'];
	if (claims && typeof claims === 'object' && !Array.isArray(claims)) {
		for (const [key, value] of Object.entries(claims)) {
			if (Array.isArray(value) || (value && typeof value === 'object')) {
				scopes.add(key);
			}
		}
	}
	return [...scopes].filter((scope) => !isStandardOidcScope(scope)).sort();
}

function descriptionsOf(value: unknown): Record<string, string> {
	if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
	return Object.fromEntries(
		Object.entries(value).filter(
			(entry): entry is [string, string] => typeof entry[1] === 'string'
		)
	);
}

export function ScopeDescriptionsField({
	values,
	disabled,
	onChange
}: {
	values: Values;
	disabled: boolean;
	onChange: (descriptions: Record<string, string>) => void;
}) {
	const descriptions = descriptionsOf(values['consent.scopeDescriptions']);
	const defined = definedCustomScopes(values);
	const orphaned = Object.keys(descriptions).filter(
		(scope) => !defined.includes(scope)
	);

	const set = (scope: string, text: string) => {
		const next = { ...descriptions };
		if (text.trim()) next[scope] = text;
		else delete next[scope];
		onChange(next);
	};

	if (!defined.length && !orphaned.length) {
		return (
			<Typography.Text type="secondary">
				This instance defines no scopes of its own beyond the standard ones, so
				there is nothing to describe.
			</Typography.Text>
		);
	}

	return (
		<div
			style={{
				display: 'flex',
				flexDirection: 'column',
				gap: 8,
				width: '100%',
				maxWidth: 560
			}}
		>
			{defined.map((scope) => (
				<Space.Compact
					key={scope}
					block
				>
					<Space.Addon>
						<Typography.Text code>{scope}</Typography.Text>
					</Space.Addon>
					<Input
						value={descriptions[scope] ?? ''}
						maxLength={200}
						placeholder="not described — shown by its name only"
						disabled={disabled}
						onChange={(e) => set(scope, e.target.value)}
					/>
				</Space.Compact>
			))}
			{orphaned.length > 0 && (
				<Alert
					type="warning"
					showIcon
					title="Described scopes that are no longer defined"
					description={
						<div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
							<span>
								Saving is refused while these remain. Remove them, or define the
								scope again.
							</span>
							{orphaned.map((scope) => (
								<span key={scope}>
									<Typography.Text code>{scope}</Typography.Text>{' '}
									<Button
										size="small"
										type="text"
										icon={<DeleteOutlined />}
										aria-label={`Remove the description of ${scope}`}
										disabled={disabled}
										onClick={() => set(scope, '')}
									/>
								</span>
							))}
						</div>
					}
				/>
			)}
		</div>
	);
}
