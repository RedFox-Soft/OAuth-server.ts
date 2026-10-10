import { theme } from 'antd';
import type { Sum } from '../../../activity/overview.js';

/*
 * The usage dashboard's three charts (specs/077), drawn as plain SVG: thirteen bars, two months of days and a
 * thirteen-point trend do not justify a chart library and its dependency tree in the console bundle.
 *
 * The kinds of activity are drawn beside a month's total, never stacked into it: one person who signed in
 * and later only renewed counts once in the total and once in each kind, so the kinds add up to more than
 * the total and a stacked bar would show a number nobody counted.
 */

const KIND_KEYS = ['local', 'federated', 'renewal'] as const;
const KIND_NAMES = {
	local: 'local',
	federated: 'upstream',
	renewal: 'renewal'
};

function niceMax(values: readonly number[]): number {
	return Math.max(1, ...values);
}

export function MonthBars({
	labels,
	sums
}: {
	/* Oldest first. */
	labels: readonly string[];
	sums: readonly (Sum | null)[];
}) {
	const { token } = theme.useToken();
	const width = 720;
	const height = 200;
	const top = 18;
	const bottom = 22;
	const slot = width / Math.max(1, labels.length);
	const max = niceMax(
		sums.flatMap((sum) =>
			sum === null ? [] : [sum.total, ...KIND_KEYS.map((k) => sum.byKind[k])]
		)
	);
	const scale = (value: number) => ((height - top - bottom) * value) / max;
	const kindColours = [
		token.colorInfo,
		token.colorWarning,
		token.colorTextQuaternary
	];
	const description = labels
		.map((label, i) => {
			const sum = sums[i];
			return sum === null
				? `${label}: no figure`
				: `${label}: ${String(sum.total)}${sum.final ? '' : ' so far'}`;
		})
		.join('; ');

	return (
		<svg
			viewBox={`0 0 ${String(width)} ${String(height)}`}
			width="100%"
			role="img"
			style={{ maxWidth: width, display: 'block' }}
		>
			<title>{`Monthly active users by month — ${description}`}</title>
			<defs>
				<pattern
					id="usage-open-month"
					width="6"
					height="6"
					patternUnits="userSpaceOnUse"
					patternTransform="rotate(45)"
				>
					<rect
						width="6"
						height="6"
						fill={token.colorPrimaryBg}
					/>
					<line
						x1="0"
						y1="0"
						x2="0"
						y2="6"
						stroke={token.colorPrimary}
						strokeWidth="3"
					/>
				</pattern>
			</defs>
			{labels.map((label, i) => {
				const sum = sums[i];
				const x = i * slot;
				const base = height - bottom;
				const barWidth = slot * 0.42;
				const thin = (slot * 0.36) / KIND_KEYS.length;
				return (
					<g key={label}>
						{sum === null ? null : (
							<>
								<rect
									x={x + slot * 0.08}
									y={base - scale(sum.total)}
									width={barWidth}
									height={scale(sum.total)}
									fill={
										sum.final ? token.colorPrimary : 'url(#usage-open-month)'
									}
								/>
								<text
									x={x + slot * 0.08 + barWidth / 2}
									y={base - scale(sum.total) - 4}
									textAnchor="middle"
									fontSize="10"
									fill={token.colorText}
								>
									{sum.final ? String(sum.total) : `${String(sum.total)}…`}
								</text>
								{KIND_KEYS.map((kind, k) => (
									<rect
										key={kind}
										x={x + slot * 0.54 + k * thin}
										y={base - scale(sum.byKind[kind])}
										width={thin * 0.8}
										height={scale(sum.byKind[kind])}
										fill={kindColours[k]}
									>
										<title>{`${label} ${KIND_NAMES[kind]}: ${String(sum.byKind[kind])}`}</title>
									</rect>
								))}
							</>
						)}
						<text
							x={x + slot / 2}
							y={height - 6}
							textAnchor="middle"
							fontSize="10"
							fill={token.colorTextSecondary}
						>
							{label.slice(2)}
						</text>
					</g>
				);
			})}
		</svg>
	);
}

export function MonthLegend() {
	const { token } = theme.useToken();
	const items = [
		{ name: 'active users (hatched: so far)', colour: token.colorPrimary },
		{ name: 'local sign-in', colour: token.colorInfo },
		{ name: 'upstream sign-in', colour: token.colorWarning },
		{ name: 'renewal', colour: token.colorTextQuaternary }
	];
	return (
		<div
			style={{
				display: 'flex',
				flexWrap: 'wrap',
				gap: 12,
				fontSize: 12,
				color: token.colorTextSecondary
			}}
		>
			{items.map((item) => (
				<span key={item.name}>
					<span
						style={{
							display: 'inline-block',
							width: 10,
							height: 10,
							marginRight: 4,
							background: item.colour
						}}
					/>
					{item.name}
				</span>
			))}
		</div>
	);
}

export function DayBars({
	days,
	previousDays,
	month,
	previousMonth
}: {
	days: readonly (number | null)[];
	previousDays: readonly (number | null)[];
	month: string;
	previousMonth: string;
}) {
	const { token } = theme.useToken();
	const width = 720;
	const height = 160;
	const bottom = 18;
	const count = Math.max(days.length, previousDays.length, 1);
	const slot = width / count;
	const max = niceMax([...days, ...previousDays].map((v) => v ?? 0));
	const scale = (value: number) => ((height - bottom - 6) * value) / max;
	const base = height - bottom;

	return (
		<svg
			viewBox={`0 0 ${String(width)} ${String(height)}`}
			width="100%"
			role="img"
			style={{ maxWidth: width, display: 'block' }}
		>
			<title>{`Daily active users of ${month}, drawn over ${previousMonth}`}</title>
			{previousDays.map((value, i) =>
				value === null ? null : (
					<rect
						key={`p${String(i)}`}
						x={i * slot + slot * 0.1}
						y={base - scale(value)}
						width={slot * 0.8}
						height={scale(value)}
						fill={token.colorFillSecondary}
					/>
				)
			)}
			{days.map((value, i) =>
				value === null ? null : (
					<rect
						key={`c${String(i)}`}
						x={i * slot + slot * 0.3}
						y={base - scale(value)}
						width={slot * 0.4}
						height={scale(value)}
						fill={token.colorPrimary}
					/>
				)
			)}
			{Array.from({ length: count }, (_, i) =>
				(i + 1) % 5 === 0 || i === 0 ? (
					<text
						key={`l${String(i)}`}
						x={i * slot + slot / 2}
						y={height - 4}
						textAnchor="middle"
						fontSize="10"
						fill={token.colorTextSecondary}
					>
						{String(i + 1)}
					</text>
				) : null
			)}
		</svg>
	);
}

export function Sparkline({
	values,
	lastFinal
}: {
	/* Oldest first; `null` before the bucket existed. */
	values: readonly (number | null)[];
	lastFinal: boolean;
}) {
	const { token } = theme.useToken();
	const width = 96;
	const height = 24;
	const step = width / Math.max(1, values.length - 1);
	const max = niceMax(values.map((v) => v ?? 0));
	const points = values
		.map((value, i) =>
			value === null
				? null
				: `${(i * step).toFixed(1)},${(height - 2 - ((height - 4) * value) / max).toFixed(1)}`
		)
		.filter((point): point is string => point !== null);
	const last = values.at(-1) ?? null;
	const [lastX, lastY] = (points.at(-1) ?? '0,0').split(',').map(Number);

	return (
		<svg
			width={width}
			height={height}
			role="img"
		>
			<title>
				{values.map((v) => (v === null ? '—' : String(v))).join(', ')}
			</title>
			<polyline
				points={points.join(' ')}
				fill="none"
				stroke={token.colorPrimary}
				strokeWidth="1.5"
			/>
			{last === null ? null : (
				<circle
					cx={lastX}
					cy={lastY}
					r="2.5"
					fill={lastFinal ? token.colorPrimary : token.colorBgContainer}
					stroke={token.colorPrimary}
				/>
			)}
		</svg>
	);
}
