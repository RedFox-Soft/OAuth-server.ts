import { useEffect, useMemo, useState, type ReactNode } from 'react';
import {
	Alert,
	Button,
	Card,
	Checkbox,
	Flex,
	Input,
	InputNumber,
	Radio,
	Select,
	Space,
	Tag,
	Typography
} from 'antd';
import { DeleteOutlined, PlusOutlined } from '@ant-design/icons';
import { request } from '../../frame/request.js';
import {
	inAnyWindow,
	minuteOfWeek,
	type TimeWindow
} from '../../../../behind_proxy/clock.js';
import {
	CLAIM_KEY,
	CLAIM_PREFIX,
	isSelectableAttribute,
	MIN_FRESH_MINUTES,
	MAX_FRESH_MINUTES,
	PROFILE_ATTRIBUTES,
	type Condition,
	type ConditionKind
} from '../../../../behind_proxy/conditions.js';
import {
	ATTRIBUTE_LABELS,
	clock,
	DAYS,
	KIND_LABELS,
	windowText
} from './conditionsText.js';

/*
 * The conditions of one rule, or of an API (specs/124 FR-023, FR-025): one card per kind, at most one of each, in the
 * order they are decided. Edits go back to the caller, which saves them with its own save bar — the editor saves
 * nothing itself.
 */

const STEPS = Array.from({ length: 96 }, (_, i) => i * 15);
const STEP_OPTIONS = STEPS.map((minute) => ({
	value: minute,
	label: clock(minute)
}));
const FRESH_PRESETS = [15, 60, 480, 1440];

const BROWSER_ZONE = (() => {
	try {
		return Intl.DateTimeFormat().resolvedOptions().timeZone;
	} catch {
		return 'UTC';
	}
})();

function zones(): string[] {
	const all =
		typeof Intl.supportedValuesOf === 'function'
			? Intl.supportedValuesOf('timeZone')
			: ['UTC'];
	return [BROWSER_ZONE, ...all.filter((zone) => zone !== BROWSER_ZONE)];
}

function blank(kind: ConditionKind): Condition {
	switch (kind) {
		case 'network':
			return { kind, only: [], not: [] };
		case 'time':
			return {
				kind,
				windows: [{ days: [0, 1, 2, 3, 4], start: 8 * 60, end: 20 * 60 }]
			};
		case 'attribute':
			return { kind, attribute: 'department', values: [] };
		case 'fresh':
			return { kind, maxAgeMinutes: 15 };
		case 'group':
			return { kind, groupIds: [] };
	}
}

function lines(text: string): string[] {
	return text
		.split(/\r?\n/)
		.map((line) => line.trim())
		.filter((line) => line !== '');
}

export function ConditionsEditor({
	conditions,
	kinds,
	inherited = [],
	timeZone,
	onTimeZone,
	groups = [],
	countUrl,
	disabled,
	unavailable = {},
	onChange
}: {
	conditions: Condition[];
	/*
	 * Kinds that cannot be added yet, with why and what to do first: told before anything is typed, since a save the
	 * server refuses would send the administrator to another tab and lose the draft.
	 */
	unavailable?: Partial<Record<ConditionKind, ReactNode>>;
	/* The kinds this place may hold, in decision order. */
	kinds: readonly ConditionKind[];
	/* Conditions from the paths above, shown and not editable here. */
	inherited?: { from: string; text: string }[];
	timeZone: string | null;
	onTimeZone: (zone: string | null) => void;
	groups?: { id: string; displayName: string }[];
	/* `…/attribute-matches` of the project, for the count beside an attribute condition. */
	countUrl: string;
	disabled: boolean;
	onChange: (conditions: Condition[]) => void;
}) {
	const present = new Set(conditions.map((c) => c.kind));
	const missing = kinds.filter((kind) => !present.has(kind));
	const blocked = missing.filter((kind) => unavailable[kind] !== undefined);
	const ordered = [...conditions].sort(
		(a, b) => kinds.indexOf(a.kind) - kinds.indexOf(b.kind)
	);

	function replace(next: Condition) {
		onChange(conditions.map((c) => (c.kind === next.kind ? next : c)));
	}

	function remove(kind: ConditionKind) {
		onChange(conditions.filter((c) => c.kind !== kind));
	}

	return (
		<Flex
			vertical
			gap={12}
		>
			<Typography.Text type="secondary">
				A person needs every condition below
				{inherited.length > 0 ? ', and the ones from the paths above' : ''}.
			</Typography.Text>
			{inherited.map((line) => (
				<Typography.Text
					key={`${line.from}:${line.text}`}
					type="secondary"
				>
					{line.text} (from {line.from})
				</Typography.Text>
			))}
			{ordered.map((condition) => (
				<Card
					key={condition.kind}
					size="small"
					title={KIND_LABELS[condition.kind]}
					extra={
						!disabled && (
							<Button
								aria-label={`Remove the ${KIND_LABELS[condition.kind]} condition`}
								icon={<DeleteOutlined />}
								size="small"
								onClick={() => remove(condition.kind)}
							/>
						)
					}
				>
					{condition.kind === 'network' && (
						<NetworkFields
							condition={condition}
							disabled={disabled}
							onChange={replace}
						/>
					)}
					{condition.kind === 'time' && (
						<TimeFields
							condition={condition}
							timeZone={timeZone}
							onTimeZone={onTimeZone}
							disabled={disabled}
							onChange={replace}
						/>
					)}
					{condition.kind === 'attribute' && (
						<AttributeFields
							condition={condition}
							countUrl={countUrl}
							disabled={disabled}
							onChange={replace}
						/>
					)}
					{condition.kind === 'fresh' && (
						<FreshFields
							condition={condition}
							disabled={disabled}
							onChange={replace}
						/>
					)}
					{condition.kind === 'group' && (
						<Select
							mode="multiple"
							aria-label="Groups"
							placeholder="Choose groups"
							style={{ width: '100%' }}
							value={condition.groupIds}
							disabled={disabled}
							options={groups.map((g) => ({
								value: g.id,
								label: g.displayName
							}))}
							onChange={(groupIds: string[]) =>
								replace({ kind: 'group', groupIds })
							}
							tagRender={({ value, label, closable, onClose }) => {
								const known = groups.some((g) => g.id === value);
								return (
									<Tag
										color={known ? undefined : 'red'}
										closable={closable}
										onClose={onClose}
									>
										{known ? label : 'Deleted group'}
									</Tag>
								);
							}}
						/>
					)}
				</Card>
			))}
			{!disabled && missing.length > 0 && (
				<Select<ConditionKind>
					aria-label="Add a condition"
					placeholder={
						<span>
							<PlusOutlined /> Add condition
						</span>
					}
					style={{ width: 240 }}
					value={null}
					options={missing.map((kind) => ({
						value: kind,
						label: KIND_LABELS[kind],
						disabled: unavailable[kind] !== undefined
					}))}
					onChange={(kind) => onChange([...conditions, blank(kind)])}
				/>
			)}
			{!disabled &&
				blocked.map((kind) => (
					<Typography.Text
						key={kind}
						type="secondary"
					>
						{unavailable[kind]}
					</Typography.Text>
				))}
		</Flex>
	);
}

function NetworkFields({
	condition,
	disabled,
	onChange
}: {
	condition: Extract<Condition, { kind: 'network' }>;
	disabled: boolean;
	onChange: (next: Condition) => void;
}) {
	const [only, setOnly] = useState(condition.only.join('\n'));
	const [not, setNot] = useState(condition.not.join('\n'));
	const noIpv6 =
		condition.not.length > 0 && !condition.not.some((r) => r.includes(':'));
	return (
		<Flex
			vertical
			gap={8}
		>
			<Typography.Text>Only from</Typography.Text>
			<Input.TextArea
				aria-label="Only from"
				placeholder={'203.0.113.0/24\n198.51.100.7'}
				autoSize={{ minRows: 2, maxRows: 8 }}
				value={only}
				disabled={disabled}
				onChange={(e) => {
					setOnly(e.target.value);
					onChange({ ...condition, only: lines(e.target.value) });
				}}
			/>
			<Typography.Text type="secondary">
				Any one of these is enough. One address or range per line.
			</Typography.Text>
			<Typography.Text>Not from</Typography.Text>
			<Input.TextArea
				aria-label="Not from"
				autoSize={{ minRows: 1, maxRows: 8 }}
				value={not}
				disabled={disabled}
				onChange={(e) => {
					setNot(e.target.value);
					onChange({ ...condition, not: lines(e.target.value) });
				}}
			/>
			{noIpv6 && (
				<Typography.Text type="warning">
					This list has no IPv6 ranges. People connecting over IPv6 are not
					checked against it.
				</Typography.Text>
			)}
			<Typography.Text type="secondary">
				If FoxAuth cannot tell the address, the request is refused. A VPN or a
				residential proxy can still get around a list: it slows an attacker, it
				does not stop one.
			</Typography.Text>
		</Flex>
	);
}

function TimeFields({
	condition,
	timeZone,
	onTimeZone,
	disabled,
	onChange
}: {
	condition: Extract<Condition, { kind: 'time' }>;
	timeZone: string | null;
	onTimeZone: (zone: string | null) => void;
	disabled: boolean;
	onChange: (next: Condition) => void;
}) {
	const zoneOptions = useMemo(
		() =>
			zones().map((zone, i) => ({
				value: zone,
				label: i === 0 ? `Your browser: ${zone}` : zone
			})),
		[]
	);
	const [now, setNow] = useState(() => Date.now());
	useEffect(() => {
		const timer = setInterval(() => setNow(Date.now()), 30_000);
		return () => clearInterval(timer);
	}, []);

	function setWindow(index: number, next: TimeWindow) {
		onChange({
			...condition,
			windows: condition.windows.map((w, i) => (i === index ? next : w))
		});
	}

	const minute = timeZone ? minuteOfWeek(now, timeZone) : null;
	return (
		<Flex
			vertical
			gap={8}
		>
			<Select
				showSearch
				aria-label="Time zone"
				placeholder="Choose the time zone the hours are in"
				style={{ width: '100%' }}
				value={timeZone}
				disabled={disabled}
				options={zoneOptions}
				onChange={(zone: string) => onTimeZone(zone)}
			/>
			{condition.windows.map((window, index) => (
				<Flex
					key={index}
					gap={8}
					wrap
					align="center"
				>
					<Checkbox.Group
						aria-label="Days"
						value={window.days}
						disabled={disabled}
						options={DAYS.map((label, day) => ({ value: day, label }))}
						onChange={(days) =>
							setWindow(index, {
								...window,
								days: [...days].sort((a, b) => a - b)
							})
						}
					/>
					<Select
						aria-label="Opens at"
						style={{ width: 90 }}
						value={window.start}
						disabled={disabled}
						options={STEP_OPTIONS}
						onChange={(start: number) => setWindow(index, { ...window, start })}
					/>
					<span>to</span>
					<Select
						aria-label="Closes at"
						style={{ width: 90 }}
						value={window.end}
						disabled={disabled}
						options={STEP_OPTIONS}
						onChange={(end: number) => setWindow(index, { ...window, end })}
					/>
					<Typography.Text type="secondary">
						{windowText(window)}
					</Typography.Text>
					{!disabled && condition.windows.length > 1 && (
						<Button
							aria-label="Remove this window"
							size="small"
							icon={<DeleteOutlined />}
							onClick={() =>
								onChange({
									...condition,
									windows: condition.windows.filter((_, i) => i !== index)
								})
							}
						/>
					)}
				</Flex>
			))}
			{!disabled && condition.windows.length < 7 && (
				<Button
					size="small"
					icon={<PlusOutlined />}
					style={{ alignSelf: 'flex-start' }}
					onClick={() =>
						onChange({
							...condition,
							windows: [
								...condition.windows,
								{ days: [5], start: 10 * 60, end: 14 * 60 }
							]
						})
					}
				>
					Add hours
				</Button>
			)}
			{timeZone && minute !== null ? (
				<Typography.Text type="secondary">
					Now in {timeZone}: {DAYS[Math.floor(minute / 1440)]}{' '}
					{clock(minute % 1440)},{' '}
					{inAnyWindow(condition.windows, minute)
						? 'inside the hours'
						: 'outside the hours'}
					.
				</Typography.Text>
			) : (
				<Alert
					type="warning"
					showIcon
					title="Choose the time zone the hours are in."
				/>
			)}
		</Flex>
	);
}

function AttributeFields({
	condition,
	countUrl,
	disabled,
	onChange
}: {
	condition: Extract<Condition, { kind: 'attribute' }>;
	countUrl: string;
	disabled: boolean;
	onChange: (next: Condition) => void;
}) {
	const isClaim = condition.attribute.startsWith(CLAIM_PREFIX);
	/* The count, remembered with what it was counted for, so a stale count is never shown for new values. */
	const [counted, setCounted] = useState<{ key: string; count: number } | null>(
		null
	);
	const valid = isSelectableAttribute(condition.attribute);
	const countKey = `${condition.attribute}|${condition.values.join('|')}`;
	const count =
		valid && condition.values.length > 0 && counted?.key === countKey
			? counted.count
			: null;
	useEffect(() => {
		if (!valid || condition.values.length === 0) return;
		const query = new URLSearchParams({ attribute: condition.attribute });
		for (const value of condition.values) query.append('value', value);
		let current = true;
		const timer = setTimeout(() => {
			void request<{ count: number }>(
				'GET',
				`${countUrl}?${query.toString()}`
			).then((result) => {
				if (current && result.ok) {
					setCounted({ key: countKey, count: result.data.count });
				}
			});
		}, 300);
		return () => {
			current = false;
			clearTimeout(timer);
		};
	}, [countUrl, condition.attribute, condition.values, valid, countKey]);

	return (
		<Flex
			vertical
			gap={8}
		>
			<Flex
				gap={8}
				wrap
			>
				<Select
					aria-label="Attribute"
					style={{ width: 200 }}
					value={isClaim ? 'claim' : condition.attribute}
					disabled={disabled}
					options={[
						...PROFILE_ATTRIBUTES.map((name) => ({
							value: name,
							label: ATTRIBUTE_LABELS[name]
						})),
						{ value: 'claim', label: 'Custom claim' }
					]}
					onChange={(value: string) =>
						onChange({
							...condition,
							attribute: value === 'claim' ? CLAIM_PREFIX : value
						})
					}
				/>
				{isClaim && (
					<Input
						aria-label="Claim name"
						style={{ width: 200 }}
						placeholder="cost_center"
						value={condition.attribute.slice(CLAIM_PREFIX.length)}
						disabled={disabled}
						status={
							condition.attribute.length > CLAIM_PREFIX.length && !valid
								? 'error'
								: undefined
						}
						onChange={(e) =>
							onChange({
								...condition,
								attribute: `${CLAIM_PREFIX}${e.target.value.trim()}`
							})
						}
					/>
				)}
			</Flex>
			{isClaim && (
				<Typography.Text type="secondary">
					A claim an administrator sets on the person. Claims a person&apos;s
					outside sign-in provider supplies (their name, picture, language)
					cannot be used: the person can change them.
					{!CLAIM_KEY.test(condition.attribute.slice(CLAIM_PREFIX.length)) &&
						condition.attribute.length > CLAIM_PREFIX.length &&
						' This name is not allowed.'}
				</Typography.Text>
			)}
			<Select
				mode="tags"
				aria-label="Values"
				placeholder="Ops"
				style={{ width: '100%' }}
				value={condition.values}
				disabled={disabled}
				open={false}
				onChange={(values: string[]) => onChange({ ...condition, values })}
			/>
			<Typography.Text type="secondary">
				Any one of these is enough; letter case counts.
			</Typography.Text>
			{count !== null && (
				<Typography.Text type={count === 0 ? 'danger' : 'secondary'}>
					{count === 0
						? 'Nobody in this project matches, so this would turn everyone away.'
						: `${String(count)} ${count === 1 ? 'person' : 'people'} in this project match.`}
				</Typography.Text>
			)}
		</Flex>
	);
}

function FreshFields({
	condition,
	disabled,
	onChange
}: {
	condition: Extract<Condition, { kind: 'fresh' }>;
	disabled: boolean;
	onChange: (next: Condition) => void;
}) {
	const preset = FRESH_PRESETS.includes(condition.maxAgeMinutes);
	return (
		<Flex
			vertical
			gap={8}
		>
			<Flex
				gap={8}
				wrap
				align="center"
			>
				<Typography.Text>Ask to sign in again every</Typography.Text>
				<Radio.Group
					value={preset ? condition.maxAgeMinutes : 'custom'}
					disabled={disabled}
					onChange={(e) => {
						const value = e.target.value as number | 'custom';
						if (value !== 'custom')
							onChange({ ...condition, maxAgeMinutes: value });
					}}
					options={[
						{ value: 15, label: '15 min' },
						{ value: 60, label: '1 h' },
						{ value: 480, label: '8 h' },
						{ value: 1440, label: '1 day' },
						{ value: 'custom', label: 'Custom' }
					]}
				/>
				{!preset && (
					<Space.Compact>
						<InputNumber
							aria-label="Minutes"
							min={MIN_FRESH_MINUTES}
							max={MAX_FRESH_MINUTES}
							value={condition.maxAgeMinutes}
							disabled={disabled}
							onChange={(value) =>
								typeof value === 'number' &&
								onChange({ ...condition, maxAgeMinutes: value })
							}
						/>
						<Button disabled>min</Button>
					</Space.Compact>
				)}
			</Flex>
			<Checkbox
				checked={condition.withCode === true}
				disabled={disabled}
				onChange={(e) => {
					const { withCode: _was, ...plain } = condition;
					onChange(
						e.target.checked ? { ...plain, withCode: true as const } : plain
					);
				}}
			>
				with a code from an authenticator app
			</Checkbox>
			{condition.withCode && (
				<Typography.Text type="secondary">
					People without one, and people who sign in through a provider, can’t
					open this path. People without one are asked to set one up when the
					project lets them.
				</Typography.Text>
			)}
			<Typography.Text type="secondary">
				Pages that load data in the background, such as dashboards, stop working
				until the person reloads the page. Use this on admin paths, not on the
				whole app.
				{condition.withCode
					? ''
					: ' A person who signs in through an outside provider is asked to sign in there again; how fresh that sign-in is, the provider decides.'}
			</Typography.Text>
		</Flex>
	);
}
