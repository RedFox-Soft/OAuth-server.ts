import { useCallback, useEffect, useMemo, useState } from 'react';
import type { MouseEvent } from 'react';
import {
	Alert,
	Button,
	Card,
	Checkbox,
	Col,
	Collapse,
	Drawer,
	Empty,
	Input,
	Popover,
	Row,
	Segmented,
	Select,
	Space,
	Statistic,
	Table,
	Tag,
	Tooltip,
	Typography
} from 'antd';
import { DownloadOutlined, QuestionCircleOutlined } from '@ant-design/icons';
import { readJson } from '../json.js';
import {
	changeText,
	figureText,
	isFiltered,
	visibleRows,
	type CustomerRef,
	type CustomerSummary,
	type OverviewAnswer,
	type OverviewRow,
	type SharpChange
} from '../activity/model.js';
import {
	customerKey,
	customerSummaries,
	instanceSummary,
	sharpChanges,
	type CustomerDetails
} from '../../../activity/overview.js';
import {
	endOf,
	monthOf,
	monthsBack,
	startOf
} from '../../../activity/periods.js';
import { usageCsv } from '../activity/csv.js';
import {
	DayBars,
	MonthBars,
	MonthLegend,
	Sparkline
} from '../activity/charts.js';
import {
	loadPreferences,
	savePreferences,
	type UsagePreferences
} from '../activity/preferences.js';
import { BucketActivityPanel } from './BucketActivityPanel.js';
import { BucketDetail } from './BucketDetail.js';
import { UsageCustomerDrawer } from './UsageCustomerDrawer.js';

/*
 * The super administrator's usage dashboard (specs/077): every bucket's monthly active users beside the
 * customer that owns it, the instance at a glance, and what changed sharply.
 *
 * The server answers every bucket at once; the search and the filters run here, and every total, chart and
 * the sharp-changes list is recomputed over exactly the rows they leave, with the server's own functions —
 * so a total on screen always describes the rows on screen.
 */

/* How far back the month picker reaches: the thirteen months a bucket's history shows, and a year before. */
const MONTHS_OFFERED = 25;

const WHAT_COUNTS = (
	<div style={{ maxWidth: 360 }}>
		<p>
			A monthly active user is a person a bucket issued tokens to — a sign-in, a
			refresh, a silent re-authentication — counted once per calendar month in
			UTC.
		</p>
		<p>
			Local, upstream and renewal say how they were active. One person can be
			active in more than one way, so the three add up to more than the total.
		</p>
		<p>
			A customer is the group that owns a bucket. Its figure is the sum of its
			buckets&apos; figures, not a count of distinct people.
		</p>
	</div>
);

interface DayRow {
	day: number;
	current: number | null;
	previous: number | null;
	final: boolean;
}

function compareOptional(a: number | null, b: number | null): number {
	return (a ?? -1) - (b ?? -1);
}

function changeValue(row: OverviewRow): number | null {
	const current = row.months[0];
	const previous = row.months[1];
	return current && previous ? current.total - previous.total : null;
}

/* `null` when the request itself failed — no answer, as opposed to a refusal, which is an answer. */
async function readOverview(asked: string): Promise<{
	ok: boolean;
	body: OverviewAnswer & { message?: string };
} | null> {
	try {
		const query = asked ? `?month=${encodeURIComponent(asked)}` : '';
		const res = await fetch(`/admin/api/activity${query}`);
		return {
			ok: res.ok,
			body: await readJson<OverviewAnswer & { message?: string }>(res)
		};
	} catch {
		return null;
	}
}

function nowrap(text: string) {
	return <span style={{ whiteSpace: 'nowrap' }}>{text}</span>;
}

function stop(event: MouseEvent) {
	event.stopPropagation();
}

export function Usage() {
	const [month, setMonth] = useState('');
	const [answer, setAnswer] = useState<OverviewAnswer | null>(null);
	const [refusal, setRefusal] = useState<string | null>(null);
	const [failed, setFailed] = useState(false);
	const [loading, setLoading] = useState(true);
	const [search, setSearch] = useState('');
	const [preferences, setPreferences] =
		useState<UsagePreferences>(loadPreferences);
	const [openBucketId, setOpenBucketId] = useState<string | null>(null);
	const [historyOf, setHistoryOf] = useState<OverviewRow | null>(null);
	const [customerOf, setCustomerOf] = useState<string | null>(null);

	// Every state write follows an await, so the effect below sets nothing synchronously.
	const fetchAnswer = useCallback(async (asked: string) => {
		try {
			const read = await readOverview(asked);
			/* No stale figures after a failed read: the page shows the failure and a retry, nothing else. */
			setFailed(read === null);
			setAnswer(read?.ok ? read.body : null);
			setRefusal(
				read === null || read.ok ? null : (read.body.message ?? 'unavailable')
			);
		} finally {
			setLoading(false);
		}
	}, []);

	useEffect(() => {
		void fetchAnswer(month);
	}, [fetchAnswer, month]);

	const update = (patch: Partial<UsagePreferences>) => {
		const next = { ...preferences, ...patch };
		setPreferences(next);
		savePreferences(next);
	};

	const filters = useMemo(
		() => ({ search, ...preferences }),
		[search, preferences]
	);
	const rows = useMemo(
		() => (answer ? visibleRows(answer.buckets, filters) : []),
		[answer, filters]
	);
	const isCurrent = answer
		? answer.month === monthOf(new Date(answer.asOf))
		: false;
	const instance = useMemo(
		() =>
			answer ? instanceSummary(rows, answer.months.length, isCurrent) : null,
		[answer, rows, isCurrent]
	);
	const details = useMemo(
		() =>
			new Map<string, CustomerDetails>(
				(answer?.customers ?? []).map((c) => [
					customerKey(c.customer),
					{ contacts: c.contacts, memberCount: c.memberCount }
				])
			),
		[answer]
	);
	const customers = useMemo(
		() => customerSummaries(rows, details),
		[rows, details]
	);
	const changes = useMemo(() => {
		if (!answer || answer.changes.to === null) return null;
		return sharpChanges(
			rows,
			answer.months,
			answer.months.indexOf(answer.changes.to)
		);
	}, [answer, rows]);

	if (openBucketId) {
		return (
			<BucketDetail
				bucketId={openBucketId}
				onBack={() => setOpenBucketId(null)}
			/>
		);
	}

	const thisMonth = monthOf(new Date());
	const monthOptions = monthsBack(thisMonth, MONTHS_OFFERED).map((m) => ({
		value: m === thisMonth ? '' : m,
		label: m === thisMonth ? `${m} (this month)` : m
	}));

	const customerCell = (customer: CustomerRef) =>
		customer.exists && customer.groupId !== null ? (
			<Button
				type="link"
				size="small"
				style={{ padding: 0 }}
				onClick={(event) => {
					stop(event);
					setCustomerOf(customerKey(customer));
				}}
			>
				{customer.label}
			</Button>
		) : (
			<Typography.Text type="secondary">
				{customer.groupId === null
					? customer.label
					: `${customer.label} (deleted group)`}
			</Typography.Text>
		);

	const sortOrderOf = (column: string): 'ascend' | 'descend' | null =>
		preferences.sort?.column === column ? preferences.sort.order : null;

	const bucketColumns = [
		{
			title: 'Bucket',
			key: 'name',
			sorter: (a: OverviewRow, b: OverviewRow) => a.name.localeCompare(b.name),
			sortOrder: sortOrderOf('name'),
			render: (_: unknown, row: OverviewRow) => (
				<Space size={4}>
					{row.deleted === null ? (
						<Button
							type="link"
							size="small"
							style={{ padding: 0 }}
							onClick={(event) => {
								stop(event);
								setOpenBucketId(row.bucketId);
							}}
						>
							{row.name}
						</Button>
					) : (
						<span>{row.name}</span>
					)}
					{row.reserved ? <Tag>{row.reserved}</Tag> : null}
					{row.deleted ? <Tag color="red">deleted</Tag> : null}
					{row.unavailable ? <Tag color="orange">unavailable</Tag> : null}
				</Space>
			)
		},
		{
			title: (
				<Tooltip title="The group that owns the bucket now. A bucket moved to another group shows every month under its current owner.">
					Customer (current owner)
				</Tooltip>
			),
			key: 'customer',
			sorter: (a: OverviewRow, b: OverviewRow) =>
				a.customer.label.localeCompare(b.customer.label),
			sortOrder: sortOrderOf('customer'),
			render: (_: unknown, row: OverviewRow) => customerCell(row.customer)
		},
		{
			title: answer?.month ?? 'This month',
			key: 'current',
			sorter: (a: OverviewRow, b: OverviewRow) =>
				compareOptional(a.months[0]?.total ?? null, b.months[0]?.total ?? null),
			sortOrder: sortOrderOf('current'),
			render: (_: unknown, row: OverviewRow) =>
				nowrap(row.unavailable ? '—' : figureText(row.months[0] ?? null))
		},
		{
			title: answer?.previous ?? 'Previous month',
			key: 'previous',
			sorter: (a: OverviewRow, b: OverviewRow) =>
				compareOptional(a.months[1]?.total ?? null, b.months[1]?.total ?? null),
			sortOrder: sortOrderOf('previous'),
			render: (_: unknown, row: OverviewRow) =>
				nowrap(row.unavailable ? '—' : figureText(row.months[1] ?? null))
		},
		{
			title: 'Change',
			key: 'change',
			sorter: (a: OverviewRow, b: OverviewRow) =>
				compareOptional(changeValue(a), changeValue(b)),
			sortOrder: sortOrderOf('change'),
			render: (_: unknown, row: OverviewRow) =>
				nowrap(changeText(row.months[0] ?? null, row.months[1] ?? null))
		},
		{
			title: (
				<Tooltip title="Local sign-in · upstream sign-in · renewal · provisioned by a directory. One person can be in more than one.">
					Composition
				</Tooltip>
			),
			key: 'composition',
			render: (_: unknown, row: OverviewRow) => {
				const figure = row.months[0];
				return nowrap(
					figure
						? `${String(figure.byKind.local)} · ${String(figure.byKind.federated)} · ${String(figure.byKind.renewal)} · ${String(figure.provisioned)}`
						: '—'
				);
			}
		},
		{
			title: '13 months',
			key: 'trend',
			render: (_: unknown, row: OverviewRow) => (
				<Sparkline
					values={[...row.months].reverse().map((m) => m?.total ?? null)}
					lastFinal={row.months[0]?.final ?? true}
				/>
			)
		}
	];

	const customerColumns = [
		{
			title: 'Customer',
			key: 'customer',
			render: (_: unknown, summary: CustomerSummary) =>
				customerCell(summary.customer)
		},
		{
			title: 'Contacts',
			key: 'contacts',
			render: (_: unknown, summary: CustomerSummary) =>
				summary.contacts.length > 0 ? summary.contacts.join(', ') : '—'
		},
		{
			title: 'Buckets',
			key: 'buckets',
			render: (_: unknown, summary: CustomerSummary) =>
				String(summary.bucketIds.length)
		},
		{
			title: answer?.month ?? 'This month',
			key: 'current',
			render: (_: unknown, summary: CustomerSummary) =>
				figureText(summary.current)
		},
		{
			title: answer?.previous ?? 'Previous month',
			key: 'previous',
			render: (_: unknown, summary: CustomerSummary) =>
				figureText(summary.previous)
		},
		{
			title: 'Change',
			key: 'change',
			render: (_: unknown, summary: CustomerSummary) =>
				changeText(summary.current, summary.previous)
		}
	];

	const exportMonth = () => {
		if (!answer) return;
		const blob = new Blob([usageCsv(answer.month, answer.previous, rows)], {
			type: 'text/csv;charset=utf-8'
		});
		const url = URL.createObjectURL(blob);
		const link = document.createElement('a');
		link.href = url;
		link.download = `usage-${answer.month}.csv`;
		link.click();
		URL.revokeObjectURL(url);
	};

	const asOfText = answer
		? ` Figures as of ${answer.asOf.slice(0, 16).replace('T', ' ')} UTC.`
		: '';
	const countingSince = answer ? new Date(answer.countingSince) : null;
	const partlyCounted =
		answer !== null &&
		countingSince !== null &&
		countingSince.getTime() > startOf(answer.month).getTime() &&
		countingSince.getTime() < endOf(answer.month).getTime();
	const filtered = isFiltered(filters);
	const excluded = instance?.months[0]?.unavailable ?? 0;
	const change = instance?.change ?? null;

	const changeRow = (item: SharpChange) => (
		<li key={item.bucketId}>
			<Typography.Text strong>{item.name}</Typography.Text> ·{' '}
			{item.customer.label} · {String(item.from.total)} →{' '}
			{String(item.to.total)}{' '}
			<Tag color={item.absolute < 0 ? 'red' : 'green'}>
				{item.absolute > 0 ? '+' : ''}
				{String(item.absolute)}
				{item.percent === null
					? ''
					: ` (${item.absolute > 0 ? '+' : ''}${String(item.percent)} %)`}
			</Tag>
		</li>
	);

	return (
		<Space
			orientation="vertical"
			style={{ width: '100%' }}
			size="middle"
		>
			<Card>
				<Space
					orientation="vertical"
					style={{ width: '100%' }}
					size="small"
				>
					<Space
						wrap
						style={{ width: '100%', justifyContent: 'space-between' }}
					>
						<Typography.Title
							level={3}
							style={{ margin: 0 }}
						>
							Usage
						</Typography.Title>
						<Space wrap>
							<Select
								style={{ minWidth: 180 }}
								value={month}
								options={monthOptions}
								onChange={(value: string) => {
									setLoading(true);
									setMonth(value);
								}}
							/>
							<Button
								icon={<DownloadOutlined />}
								disabled={!answer}
								onClick={exportMonth}
							>
								Export CSV
							</Button>
						</Space>
					</Space>
					<Typography.Text type="secondary">
						Monthly active users of every bucket, with the customer that owns
						it.{' '}
						<Popover
							title="What counts"
							content={WHAT_COUNTS}
						>
							<QuestionCircleOutlined />
						</Popover>
						{asOfText}
					</Typography.Text>
					{partlyCounted ? (
						<Alert
							type="info"
							showIcon
							title={`Counting began on ${countingSince.toISOString().slice(0, 10)}; ${answer.month} is only partly counted.`}
						/>
					) : null}
					{refusal !== null ? (
						<Alert
							type="error"
							showIcon
							title={refusal}
						/>
					) : null}
					{failed ? (
						<Alert
							type="error"
							showIcon
							title="The figures could not be read."
							action={
								<Button
									size="small"
									onClick={() => {
										setLoading(true);
										void fetchAnswer(month);
									}}
								>
									Retry
								</Button>
							}
						/>
					) : null}
				</Space>
			</Card>

			{answer && instance ? (
				<>
					<Card
						title={`${answer.month} at a glance`}
						extra={
							<Space>
								{filtered ? <Tag color="blue">filtered</Tag> : null}
								{excluded > 0 ? (
									<Tag color="orange">{`excludes ${String(excluded)} bucket${excluded === 1 ? '' : 's'}`}</Tag>
								) : null}
							</Space>
						}
						loading={loading}
					>
						<Row gutter={[16, 16]}>
							<Col
								xs={12}
								md={4}
							>
								<Statistic
									title="Active users"
									value={figureText(instance.months[0] ?? null)}
								/>
							</Col>
							<Col
								xs={12}
								md={4}
							>
								<Statistic
									title={`Previous month (${answer.previous})`}
									value={figureText(instance.months[1] ?? null)}
								/>
							</Col>
							{change ? (
								<Col
									xs={12}
									md={4}
								>
									<Statistic
										title="Change"
										value={changeText(
											instance.months[0] ?? null,
											instance.months[1] ?? null
										)}
									/>
								</Col>
							) : null}
							<Col
								xs={12}
								md={4}
							>
								<Statistic
									title="Active buckets"
									value={instance.activeBuckets}
								/>
							</Col>
							<Col
								xs={12}
								md={4}
							>
								<Statistic
									title="Active customers"
									value={instance.activeCustomers}
								/>
							</Col>
							{instance.today !== null ? (
								<Col
									xs={12}
									md={4}
								>
									<Statistic
										title="Today so far"
										value={instance.today}
									/>
								</Col>
							) : null}
						</Row>
					</Card>

					<Card title="Trend">
						<Typography.Title level={5}>Thirteen months</Typography.Title>
						<MonthBars
							labels={[...answer.months].reverse()}
							sums={[...instance.months].reverse()}
						/>
						<MonthLegend />
						<Typography.Title
							level={5}
							style={{ marginTop: 16 }}
						>
							{`${answer.month} by day, over ${answer.previous}`}
						</Typography.Title>
						<DayBars
							days={instance.days}
							previousDays={instance.previousDays}
							month={answer.month}
							previousMonth={answer.previous}
						/>
						<Collapse
							ghost
							size="small"
							items={[
								{
									key: 'days',
									label: 'Every day as numbers',
									children: (
										<Table
											size="small"
											pagination={false}
											rowKey="day"
											dataSource={Array.from(
												{
													length: Math.max(
														instance.days.length,
														instance.previousDays.length
													)
												},
												(_, i): DayRow => ({
													day: i + 1,
													current: instance.days[i] ?? null,
													previous: instance.previousDays[i] ?? null,
													final: answer.daysFinal[i] ?? true
												})
											)}
											columns={[
												{ title: 'Day', dataIndex: 'day', key: 'day' },
												{
													title: answer.month,
													key: 'current',
													render: (_: unknown, day: DayRow) =>
														day.current === null
															? '—'
															: day.final
																? String(day.current)
																: `${String(day.current)} so far`
												},
												{
													title: answer.previous,
													key: 'previous',
													render: (_: unknown, day: DayRow) =>
														day.previous === null ? '—' : String(day.previous)
												}
											]}
										/>
									)
								}
							]}
						/>
					</Card>

					{changes ? (
						<Card
							title={`Changed sharply between ${changes.from ?? ''} and ${changes.to ?? ''}`}
						>
							{changes.falls.length === 0 && changes.rises.length === 0 ? (
								<Typography.Text type="secondary">
									Nothing changed sharply.
								</Typography.Text>
							) : (
								<Row gutter={24}>
									<Col
										xs={24}
										md={12}
									>
										<Typography.Title level={5}>Fell</Typography.Title>
										{changes.falls.length === 0 ? (
											<Typography.Text type="secondary">None.</Typography.Text>
										) : (
											<ul>{changes.falls.map(changeRow)}</ul>
										)}
									</Col>
									<Col
										xs={24}
										md={12}
									>
										<Typography.Title level={5}>Rose</Typography.Title>
										{changes.rises.length === 0 ? (
											<Typography.Text type="secondary">None.</Typography.Text>
										) : (
											<ul>{changes.rises.map(changeRow)}</ul>
										)}
									</Col>
								</Row>
							)}
						</Card>
					) : null}

					<Card>
						<Space
							orientation="vertical"
							style={{ width: '100%' }}
							size="middle"
						>
							<Space wrap>
								<Segmented
									value={preferences.view}
									options={[
										{ value: 'bucket', label: 'By bucket' },
										{ value: 'customer', label: 'By customer' }
									]}
									onChange={(value) =>
										update({
											view: value === 'customer' ? 'customer' : 'bucket'
										})
									}
								/>
								<Input.Search
									placeholder="Bucket or customer"
									allowClear
									style={{ width: 260 }}
									value={search}
									onChange={(event) => setSearch(event.target.value)}
								/>
								<Checkbox
									checked={preferences.hideInactive}
									onChange={(event) =>
										update({ hideInactive: event.target.checked })
									}
								>
									Hide inactive
								</Checkbox>
								<Checkbox
									checked={preferences.hideReserved}
									onChange={(event) =>
										update({ hideReserved: event.target.checked })
									}
								>
									Hide reserved
								</Checkbox>
								<Checkbox
									checked={preferences.hideDeleted}
									onChange={(event) =>
										update({ hideDeleted: event.target.checked })
									}
								>
									Hide deleted
								</Checkbox>
							</Space>
							{preferences.view === 'bucket' ? (
								<Table
									rowKey="bucketId"
									loading={loading}
									size="small"
									pagination={{ pageSize: 50, hideOnSinglePage: true }}
									scroll={{ x: 'max-content' }}
									columns={bucketColumns}
									dataSource={rows}
									locale={{
										emptyText: <Empty description="No bucket matches" />
									}}
									onChange={(_pagination, _filters, sorter) => {
										const one = Array.isArray(sorter) ? sorter[0] : sorter;
										update({
											sort:
												one.order && typeof one.columnKey === 'string'
													? { column: one.columnKey, order: one.order }
													: null
										});
									}}
									onRow={(row) => ({
										onClick: () => setHistoryOf(row),
										style: { cursor: 'pointer' }
									})}
								/>
							) : (
								<Table
									rowKey={(summary) => customerKey(summary.customer)}
									loading={loading}
									size="small"
									pagination={{ pageSize: 50, hideOnSinglePage: true }}
									scroll={{ x: 'max-content' }}
									columns={customerColumns}
									dataSource={customers}
									expandable={{
										expandedRowRender: (summary) => (
											<Table
												rowKey="bucketId"
												size="small"
												pagination={false}
												columns={bucketColumns.filter(
													(column) => column.key !== 'customer'
												)}
												dataSource={rows.filter((row) =>
													summary.bucketIds.includes(row.bucketId)
												)}
												onRow={(row) => ({
													onClick: () => setHistoryOf(row),
													style: { cursor: 'pointer' }
												})}
											/>
										)
									}}
								/>
							)}
						</Space>
					</Card>
				</>
			) : null}

			<Drawer
				open={historyOf !== null}
				onClose={() => setHistoryOf(null)}
				size="large"
				destroyOnHidden
				title={historyOf?.name ?? ''}
			>
				{historyOf ? (
					<BucketActivityPanel bucketId={historyOf.bucketId} />
				) : null}
			</Drawer>
			<UsageCustomerDrawer
				summary={
					customerOf === null
						? null
						: (customers.find((c) => customerKey(c.customer) === customerOf) ??
							answer?.customers.find(
								(c) => customerKey(c.customer) === customerOf
							) ??
							null)
				}
				rows={answer?.buckets ?? []}
				month={answer?.month ?? ''}
				previous={answer?.previous ?? ''}
				onClose={() => setCustomerOf(null)}
			/>
		</Space>
	);
}
