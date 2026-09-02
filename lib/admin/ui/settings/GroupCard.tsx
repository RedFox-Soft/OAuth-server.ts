import { Card, Popover, Tag, Tooltip, Typography } from 'antd';
import {
	QuestionCircleOutlined,
	SafetyCertificateOutlined
} from '@ant-design/icons';
import { Control, isWideControl } from './controls.js';
import { GroupNote } from './notes.js';
import {
	hasDetail,
	isRowEnabled,
	type Descriptor,
	type GroupView,
	type Values
} from './model.js';

/*
 * The tags that qualify a setting's label: that changing it has a security consequence, and that the
 * feature behind it tracks a draft spec. Shared by the card header and the rows so one of them
 * cannot quietly stop showing them.
 */
function Qualifiers({ d }: { d: Descriptor }) {
	return (
		<>
			{d.risk === 'security' && (
				<Tooltip title="Changing this has a security consequence. Saving it asks you to confirm.">
					<Tag
						color="orange"
						icon={<SafetyCertificateOutlined />}
					>
						security
					</Tag>
				</Tooltip>
			)}
			{d.experimental && <Tag color="purple">experimental</Tag>}
		</>
	);
}

/*
 * The long form, behind the help icon beside the label.
 *
 * Every description used to render at full length under every control, and several of them run past
 * a hundred words — so the prose, not the settings, was most of the page. Nothing is lost: the row
 * still carries its one-line summary, and this opens the paragraph that explains it.
 *
 * An icon rather than a "Why this matters" link, and it matters for more than tidiness: seventeen
 * settings have no long form worth opening, so a per-row text link left the column ragged — some
 * rows three lines tall, some two, for a reason that had nothing to do with the setting. An icon
 * that is simply absent costs no vertical space, and sitting against the label it reads as help for
 * that label rather than as an action.
 *
 * A Popover and not a Tooltip: the longest of these descriptions is several hundred characters of
 * operator guidance — the proxy setting's "wrong answer in each direction" among them — which is
 * text to dwell on and sometimes to copy. Both triggers are wired, so hovering reveals it and
 * clicking pins it open long enough to read.
 */
function Help({ d }: { d: Descriptor }) {
	if (!hasDetail(d)) return null;
	return (
		<Popover
			trigger={['hover', 'click']}
			title={d.label}
			/*
			 * Bounded in both directions: narrow enough to read as prose, and scrolling past 320px
			 * rather than growing into a panel taller than the window — the rate-limit and login-throttle
			 * descriptions are long enough for that to matter.
			 */
			content={
				<div
					style={{
						maxWidth: 380,
						maxHeight: 320,
						overflowY: 'auto'
					}}
				>
					{d.description}
				</div>
			}
		>
			<QuestionCircleOutlined
				tabIndex={0}
				aria-label={`Why ${d.label} matters`}
				style={{ color: 'var(--ant-color-text-tertiary, #00000073)' }}
			/>
		</Popover>
	);
}

/*
 * One setting: what it is on the left, its control on the right.
 *
 * A row whose prerequisite is unmet is disabled rather than removed. Hiding it meant an operator
 * could not see what enabling a feature would let them configure, and it let a dirty value vanish
 * from the page while still being part of the next submission.
 */
function Row({
	d,
	values,
	dirty,
	onChange
}: {
	d: Descriptor;
	values: Values;
	dirty: boolean;
	onChange: (key: string, value: unknown) => void;
}) {
	const enabled = isRowEnabled(d, values);
	const wide = isWideControl(d);

	return (
		<div
			style={{
				display: 'flex',
				flexWrap: 'wrap',
				gap: 16,
				alignItems: 'flex-start',
				padding: '12px 0',
				borderTop: '1px solid var(--ant-color-split, rgba(5,5,5,0.06))',
				opacity: enabled ? 1 : 0.45
			}}
		>
			<div style={{ flex: '1 1 320px', minWidth: 240 }}>
				<div
					style={{
						display: 'flex',
						alignItems: 'center',
						gap: 8,
						flexWrap: 'wrap'
					}}
				>
					<Typography.Text strong>{d.label}</Typography.Text>
					<Help d={d} />
					<Qualifiers d={d} />
					{dirty && <Tag color="blue">unsaved</Tag>}
				</div>
				<Typography.Text
					type="secondary"
					style={{ fontSize: 12 }}
				>
					{d.summary}
				</Typography.Text>
				{!enabled && (
					<div>
						<Typography.Text
							type="secondary"
							style={{ fontSize: 12, fontStyle: 'italic' }}
						>
							Available once the switch above is on.
						</Typography.Text>
					</div>
				)}
			</div>
			<div
				style={
					wide ? { flex: '1 1 100%' } : { flex: '0 0 auto', paddingTop: 2 }
				}
			>
				<Control
					d={d}
					values={values}
					disabled={!enabled}
					onChange={onChange}
				/>
			</div>
		</div>
	);
}

/*
 * One card per catalog group, which is the whole of the page's structure.
 *
 * It replaces a three-way split — a flat card of switches, an accordion, and more cards — in which
 * where a setting appeared was decided by whether it happened to have sub-settings, not by what it
 * did. "Enable DPoP" was an accordion panel and "Enable JARM" a row in a card, for no reason an
 * operator could learn. Now every group looks the same, so its shape carries no meaning to
 * misread.
 */
export function GroupCard({
	view,
	values,
	dirty,
	onChange,
	onTogglePrimaryOff
}: {
	view: GroupView;
	values: Values;
	dirty: Set<string>;
	onChange: (key: string, value: unknown) => void;
	onTogglePrimaryOff: (primary: Descriptor) => void;
}) {
	const { group, primary, rows } = view;

	return (
		<Card
			size="small"
			style={{ marginBottom: 16 }}
			title={
				<span
					style={{
						display: 'inline-flex',
						alignItems: 'center',
						gap: 8,
						flexWrap: 'wrap'
					}}
				>
					{group}
					{primary && <Help d={primary} />}
					{primary && <Qualifiers d={primary} />}
					{primary && dirty.has(primary.key) && <Tag color="blue">unsaved</Tag>}
				</span>
			}
			extra={
				primary ? (
					<Control
						d={primary}
						values={values}
						disabled={false}
						onChange={(key, value) => {
							if (value === true) onChange(key, true);
							else onTogglePrimaryOff(primary);
						}}
					/>
				) : null
			}
		>
			{primary && (
				<div style={{ paddingBottom: rows.length > 0 ? 8 : 0 }}>
					<Typography.Text type="secondary">{primary.summary}</Typography.Text>
				</div>
			)}
			{/*
			 * Above the rows rather than below them: it states what they add up to, and an operator
			 * reaching this card wants the consequence before the knobs, not after.
			 */}
			<GroupNote
				group={group}
				values={values}
			/>
			{rows.map((d) => (
				<Row
					key={d.key}
					d={d}
					values={values}
					dirty={dirty.has(d.key)}
					onChange={onChange}
				/>
			))}
		</Card>
	);
}
