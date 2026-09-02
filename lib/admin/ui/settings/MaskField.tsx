import { Input, InputNumber, Select, Tooltip, Typography } from 'antd';
import {
	buildMask,
	groupSizeOptions,
	maskStrengthBits,
	parseMask,
	type MaskSeparator
} from './model.js';

/*
 * The device flow's user-code mask, edited as the two decisions it encodes rather than as the
 * template that encodes them.
 *
 * The stored value is a string in which `*` becomes a random character and hyphen or space are
 * copied through — so what an operator is actually choosing is how many random characters the code
 * has, and how they are broken up for someone reading them off a screen and typing them on a phone.
 * The old free-text field asked for the encoding instead, which had two costs: every asterisk is a
 * character of entropy and nothing said so, and a mask with no asterisks at all was accepted and
 * issued the same code to every device (fixed at the validator in the same series of changes).
 *
 * The strength is stated in bits and not graded. What counts as enough depends on how fast the
 * verification endpoint refuses guesses, which is a rate-limit setting on another pane, so the page
 * gives the operator the figure and leaves the judgement to them — the same division the risk tags
 * use elsewhere.
 */
export function MaskField({
	value,
	charset,
	disabled,
	onChange
}: {
	value: unknown;
	charset: unknown;
	disabled: boolean;
	onChange: (mask: string) => void;
}) {
	const shape = parseMask(value);

	/*
	 * A mask this editor cannot draw — uneven groups, both separators, something typed by hand — falls
	 * back to the template field. Redrawing a valid configuration into the nearest shape the form
	 * happens to support would silently change what the server issues, which is worse than showing
	 * the string.
	 */
	if (!shape) {
		return (
			<div style={{ width: '100%', maxWidth: 360 }}>
				<Input
					disabled={disabled}
					value={typeof value === 'string' ? value : ''}
					onChange={(e) => onChange(e.target.value)}
				/>
				<Typography.Text
					type="secondary"
					style={{ fontSize: 12 }}
				>
					Template — <code>*</code> becomes a random character; hyphen and space
					are kept. Use a mask with evenly sized groups to edit it as a length
					and a separator.
				</Typography.Text>
			</div>
		);
	}

	const bits = maskStrengthBits(value, charset);
	const groupings = groupSizeOptions(shape.length);
	const emit = (next: Partial<typeof shape>) =>
		onChange(buildMask({ ...shape, ...next }));

	return (
		<div
			style={{
				display: 'flex',
				flexDirection: 'column',
				gap: 8,
				minWidth: 320
			}}
		>
			<div
				style={{
					display: 'flex',
					gap: 8,
					alignItems: 'center',
					flexWrap: 'wrap'
				}}
			>
				<InputNumber
					style={{ width: 88 }}
					min={4}
					max={16}
					step={1}
					disabled={disabled}
					value={shape.length}
					onChange={(length) => {
						if (typeof length !== 'number') return;
						/*
						 * The grouping has to be re-resolved with the length, not carried over: a group size
						 * that divided the old length may not divide the new one, and `buildMask` would then
						 * drop the separator without the operator asking.
						 */
						const options = groupSizeOptions(length);
						const groupSize = options.includes(shape.groupSize)
							? shape.groupSize
							: (options[Math.floor((options.length - 1) / 2)] ?? 0);
						emit({ length, groupSize });
					}}
				/>
				<Typography.Text type="secondary">characters, in</Typography.Text>
				<Select<string>
					style={{ width: 150 }}
					disabled={disabled || groupings.length === 0}
					value={
						shape.separator === 'none' || shape.groupSize === 0
							? 'none'
							: `${shape.separator}:${shape.groupSize}`
					}
					onChange={(picked) => {
						if (picked === 'none') {
							emit({ separator: 'none', groupSize: 0 });
							return;
						}
						const [separator, size] = picked.split(':');
						emit({
							separator: separator as MaskSeparator,
							groupSize: Number(size)
						});
					}}
					options={[
						{ label: 'one block', value: 'none' },
						...groupings.flatMap((size) => [
							{
								label: `groups of ${size}, hyphens`,
								value: `hyphen:${size}`
							},
							{
								label: `groups of ${size}, spaces`,
								value: `space:${size}`
							}
						])
					]}
				/>
			</div>

			<div
				style={{
					display: 'flex',
					gap: 12,
					alignItems: 'baseline',
					flexWrap: 'wrap'
				}}
			>
				<Tooltip title="What a device shows the person approving it. The characters shown are an example — each code is generated fresh.">
					<Typography.Text
						code
						style={{ fontSize: 15 }}
					>
						{sample(shape.length, shape.separator, shape.groupSize, charset)}
					</Typography.Text>
				</Tooltip>
				{bits !== null && (
					<Typography.Text
						type="secondary"
						style={{ fontSize: 12 }}
					>
						about {bits} bits to guess
					</Typography.Text>
				)}
			</div>
		</div>
	);
}

/*
 * A fixed example, not a random one: this renders on every keystroke, and a code that reshuffles
 * while an operator is choosing a length reads as something happening rather than as an illustration.
 * Drawn from the charset that is actually configured so the example cannot show letters for a
 * digits-only code.
 */
function sample(
	length: number,
	separator: MaskSeparator,
	groupSize: number,
	charset: unknown
): string {
	const alphabet = charset === 'digits' ? '0123456789' : 'BCDFGHJKLMNPQRSTVWXZ';
	const chars = Array.from(
		{ length },
		(_, i) => alphabet[(i * 7 + 3) % alphabet.length]
	);
	const mask = buildMask({ length, separator, groupSize });
	let taken = 0;
	return mask
		.split('')
		.map((c) => (c === '*' ? chars[taken++] : c))
		.join('');
}
