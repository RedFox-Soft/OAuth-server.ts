import { useState, type ReactNode } from 'react';
import { Input, InputNumber, Select, Switch, Typography } from 'antd';
import type { Descriptor, Values } from './model.js';
import { MaskField } from './MaskField.js';
import { RarTypesField } from './RarTypesField.js';

interface BespokeProps {
	values: Values;
	disabled: boolean;
	onChange: (key: string, value: unknown) => void;
}

/*
 * The settings whose own control replaces the one their type would give them.
 *
 * Keyed by key and gathered here rather than branched inside `Control`, which exists to know nothing
 * about individual settings. Each entry earns its place by encoding a rule the generic control
 * cannot: the type says "a string" or "an object", and what the operator is actually choosing is
 * something narrower that a plain field lets them get wrong and only learn about from a 422.
 */
const BESPOKE: Record<string, (props: BespokeProps) => ReactNode> = {
	'deviceFlow.mask': ({ values, disabled, onChange }) => (
		<MaskField
			value={values['deviceFlow.mask']}
			charset={values['deviceFlow.charset']}
			disabled={disabled}
			onChange={(mask) => onChange('deviceFlow.mask', mask)}
		/>
	),
	'richAuthorizationRequests.types': ({ values, disabled, onChange }) => (
		<RarTypesField
			value={values['richAuthorizationRequests.types']}
			enabled={values['richAuthorizationRequests.enabled'] === true}
			disabled={disabled}
			onChange={(types) => onChange('richAuthorizationRequests.types', types)}
		/>
	)
};

/*
 * A structured JSON value, edited as text and parsed on change, keeping the last valid parse as the
 * value. Held locally until it parses: submitting a half-typed document would be refused by the
 * server for a reason the operator is in the middle of fixing.
 *
 * The server stays the authority on whether the structure is acceptable — a bespoke form per
 * structured setting would restate rules that already live in validateConfiguration.
 */
function JsonField({
	value,
	onChange,
	disabled
}: {
	value: unknown;
	onChange: (parsed: unknown) => void;
	disabled?: boolean;
}) {
	const [text, setText] = useState(() => JSON.stringify(value ?? {}, null, 2));
	const [invalid, setInvalid] = useState(false);

	return (
		<div style={{ width: '100%' }}>
			<Input.TextArea
				autoSize={{ minRows: 4, maxRows: 18 }}
				status={invalid ? 'error' : undefined}
				disabled={disabled}
				value={text}
				onChange={(e) => {
					const next = e.target.value;
					setText(next);
					try {
						onChange(JSON.parse(next));
						setInvalid(false);
					} catch {
						setInvalid(true);
					}
				}}
			/>
			{invalid ? (
				<Typography.Text type="danger">Not valid JSON yet</Typography.Text>
			) : null}
		</div>
	);
}

/*
 * The control for one setting.
 *
 * A type added to the catalog without a branch here falls through to a plain text input, which
 * cannot edit a structured value — so the fallback is deliberately the least destructive one rather
 * than a throw, and the catalog's own type union is what keeps the set closed.
 */
export function Control({
	d,
	values,
	disabled,
	onChange
}: {
	d: Descriptor;
	values: Values;
	disabled: boolean;
	onChange: (key: string, value: unknown) => void;
}) {
	const bespoke = BESPOKE[d.key];
	if (bespoke) return bespoke({ values, disabled, onChange });

	const value = values[d.key];
	const set = (v: unknown) => onChange(d.key, v);

	if (d.type === 'boolean') {
		return (
			<Switch
				checked={value === true}
				disabled={disabled}
				onChange={set}
			/>
		);
	}

	if (d.type === 'number') {
		/*
		 * The unit sits beside the input rather than inside it. Every number on this page is a quantity
		 * of something and none of them used to say which, so an operator reading "900" had to open the
		 * description to learn whether it meant seconds, days or requests.
		 */
		return (
			<span style={{ display: 'inline-flex', alignItems: 'baseline', gap: 8 }}>
				<InputNumber
					style={{ width: 140 }}
					min={1}
					step={1}
					disabled={disabled}
					value={value as number}
					onChange={set}
				/>
				<Typography.Text type="secondary">{d.unit}</Typography.Text>
			</span>
		);
	}

	if (d.type === 'enum') {
		return (
			<Select
				style={{ minWidth: 220 }}
				disabled={disabled}
				value={value as string}
				options={(d.options ?? []).map((o) => ({ label: o, value: o }))}
				onChange={set}
			/>
		);
	}

	if (d.type === 'string-array') {
		return (
			<Select
				mode={d.options ? 'multiple' : 'tags'}
				style={{ minWidth: 320, maxWidth: 480 }}
				disabled={disabled}
				value={(value as string[]) ?? []}
				options={(d.options ?? []).map((o) => ({ label: o, value: o }))}
				onChange={set}
			/>
		);
	}

	if (d.type === 'json') {
		return (
			<JsonField
				value={value}
				disabled={disabled}
				onChange={set}
			/>
		);
	}

	return (
		<Input
			style={{ maxWidth: 320 }}
			disabled={disabled}
			value={(value as string) ?? ''}
			onChange={(e) => set(e.target.value)}
		/>
	);
}

/*
 * Whether this setting's control wants a line of its own rather than the right-hand column. The
 * bespoke controls are all taller than a single field, so they take the full width by definition.
 */
export const isWideControl = (d: Descriptor) =>
	d.type === 'json' || d.type === 'string-array' || d.key in BESPOKE;
