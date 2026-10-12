import { useCallback, useEffect, useState } from 'react';
import {
	Alert,
	Button,
	Card,
	Col,
	Empty,
	Flex,
	Row,
	Segmented,
	Select,
	Space,
	Statistic,
	Table,
	Tag,
	Typography
} from 'antd';
import { request } from '../frame/request.js';
import { LoadFailed } from '../frame/states.js';
import {
	changeText,
	figureRow,
	type FigureRow,
	type PeriodFigureView
} from '../activity/model.js';
import { DayBars, MonthBars, MonthLegend } from '../activity/charts.js';
import { bucketActivityCsv } from '../activity/csv.js';
import { Link, useNavigate, useRoute } from '../frame/router.js';
import { useHydrated } from '../frame/hydrated.js';

/*
 * A bucket's monthly and daily active users (specs/076), drawn with the instance Usage dashboard's own pieces
 * (specs/086) so one set of figures reads the same in both places. Counts only — the server never says who.
 *
 * The month is part of the address (`?month=`), so a month being looked at can be linked to and survives a
 * reload; choosing another replaces the address, so Back leaves the tab instead of stepping through months.
 */

export interface BucketActivityRead {
	bucketId: string;
	name: string;
	deletedAt: string | null;
	lastOwner: { groupId: string; label: string } | null;
	countingSince: string;
	month: PeriodFigureView | null;
	days: PeriodFigureView[];
	months: PeriodFigureView[];
}

const MONTHS_SHOWN = 13;

function monthOf(date: Date): string {
	return date.toISOString().slice(0, 7);
}

/* The thirteen months ending with `month`, newest first. */
function monthsBack(month: string): string[] {
	const [y, m] = month.split('-').map(Number) as [number, number];
	return Array.from({ length: MONTHS_SHOWN }, (_, i) =>
		monthOf(new Date(Date.UTC(y, m - 1 - i, 1)))
	);
}

const COLUMNS = [
	{
		title: 'Status',
		dataIndex: 'status',
		key: 'status',
		render: (status: FigureRow['status']) =>
			status === 'final' ? <Tag>Final</Tag> : <Tag color="blue">Not final</Tag>
	},
	{ title: 'Active users', dataIndex: 'total', key: 'total' },
	{ title: 'Local sign-in', dataIndex: 'local', key: 'local' },
	{ title: 'Upstream sign-in', dataIndex: 'upstream', key: 'upstream' },
	{ title: 'Renewal', dataIndex: 'renewal', key: 'renewal' },
	{ title: 'Provisioned', dataIndex: 'provisioned', key: 'provisioned' }
];

type View = 'chart' | 'table';
/* The same prefix as Usage's layout, and for its reason (lib/admin/ui/activity/preferences.ts). */
const VIEW_KEY = 'admin-console.activity.view.v2';

/* Chart or table: a viewer's habit, remembered in this browser only and never relied on. */
function loadView(): View {
	try {
		return window.localStorage.getItem(VIEW_KEY) === 'table'
			? 'table'
			: 'chart';
	} catch {
		return 'chart';
	}
}

function saveView(view: View) {
	try {
		window.localStorage.setItem(VIEW_KEY, view);
	} catch {
		/* Not remembered this time. */
	}
}

function asSum(figure: PeriodFigureView | null) {
	return figure === null ? null : { ...figure, partial: false, unavailable: 0 };
}

export function BucketActivityPanel({
	bucketId,
	usageLink = false,
	readOnly = false
}: {
	bucketId: string;
	/* A super administrator's way back up to the dashboard, at the same month. */
	usageLink?: boolean;
	/* A deleted bucket's history page: the figures, nothing that acts on a bucket. */
	readOnly?: boolean;
}) {
	const { location, query } = useRoute();
	const navigate = useNavigate();
	const hydrated = useHydrated();
	const asked = query.get('month') ?? undefined;
	const [read, setRead] = useState<BucketActivityRead | null>(null);
	const [previousDays, setPreviousDays] = useState<PeriodFigureView[]>([]);
	const [failure, setFailure] = useState<string | null>(null);
	const [loading, setLoading] = useState(true);
	const [chosenView, setChosenView] = useState<View | null>(null);
	const view: View = chosenView ?? (hydrated ? loadView() : 'chart');

	const base = `/admin/api/buckets/${encodeURIComponent(bucketId)}/activity`;

	// Every state write follows an await, so the effect below sets nothing synchronously.
	const load = useCallback(
		async (month: string | undefined) => {
			try {
				const result = await request<BucketActivityRead>(
					'GET',
					month ? `${base}?month=${encodeURIComponent(month)}` : base
				);
				if (!result.ok) {
					setFailure(result.error.message);
					return;
				}
				setFailure(null);
				setRead(result.data);
				// The month before, by day, so the days chart draws this month over it as Usage does.
				const shown = result.data.month?.period;
				const before = shown ? monthsBack(shown)[1] : undefined;
				if (before) {
					const prior = await request<BucketActivityRead>(
						'GET',
						`${base}?month=${before}`
					);
					setPreviousDays(prior.ok ? prior.data.days : []);
				}
			} finally {
				setLoading(false);
			}
		},
		[base]
	);

	useEffect(() => {
		void load(asked);
	}, [load, asked]);

	if (failure !== null) {
		return (
			<LoadFailed
				reason={failure}
				onRetry={() => {
					setLoading(true);
					void load(asked);
				}}
			/>
		);
	}

	const shown = read?.month ?? null;
	const month = shown?.period ?? asked ?? monthOf(new Date());
	const labels = monthsBack(month);
	const figureOf = new Map((read?.months ?? []).map((m) => [m.period, m]));
	const previous = figureOf.get(labels[1] ?? '') ?? null;
	const today = (read?.days ?? []).at(-1) ?? null;
	const thisMonth = monthOf(new Date());
	const countingSince = read ? read.countingSince.slice(0, 7) : null;
	/*
	 * Only answerable from the current month: an earlier month's read stops at that month, so a bucket active
	 * since then would read as never active.
	 */
	const neverActive =
		read !== null &&
		month === thisMonth &&
		read.months.every((m) => m.total === 0);

	function choose(period: string) {
		void navigate(`${location.pathname}?month=${encodeURIComponent(period)}`, {
			replace: true
		});
	}

	function setView(next: View) {
		setChosenView(next);
		saveView(next);
	}

	function exportCsv() {
		if (!read) return;
		const blob = new Blob(
			[bucketActivityCsv({ id: read.bucketId, name: read.name }, read.months)],
			{ type: 'text/csv;charset=utf-8' }
		);
		const url = URL.createObjectURL(blob);
		const link = document.createElement('a');
		link.href = url;
		link.download = `activity-${read.bucketId}-${month}.csv`;
		link.click();
		URL.revokeObjectURL(url);
	}

	// A month with no figure stays in the table as a dash, so absent never reads as zero.
	const monthRows: (Partial<FigureRow> & { key: string; period: string })[] =
		labels.map((label) => {
			const figure = figureOf.get(label);
			return figure ? figureRow(figure) : { key: label, period: label };
		});

	const viewSwitch = (
		<Segmented<View>
			size="small"
			value={view}
			onChange={setView}
			options={[
				{ value: 'chart', label: 'Chart' },
				{ value: 'table', label: 'Table' }
			]}
		/>
	);

	return (
		<Flex
			vertical
			gap={16}
		>
			<Flex
				justify="space-between"
				align="center"
				wrap
				gap={12}
			>
				<Space>
					<Typography.Text>Month</Typography.Text>
					<Select<string>
						aria-label="Month"
						value={month}
						onChange={choose}
						style={{ minWidth: 200 }}
						options={labels.map((label) => ({
							value: label,
							label: label === thisMonth ? `${label} (this month)` : label
						}))}
					/>
				</Space>
				<Space>
					<Button
						onClick={exportCsv}
						disabled={!read}
					>
						Export CSV
					</Button>
					{usageLink && !readOnly && (
						<Link href={`/admin/usage?month=${encodeURIComponent(month)}`}>
							Usage →
						</Link>
					)}
				</Space>
			</Flex>
			{countingSince !== null &&
				labels.includes(countingSince) &&
				countingSince !== labels.at(-1) && (
					<Alert
						type="info"
						showIcon
						title={`Counting began on ${new Date(read?.countingSince ?? '').toLocaleDateString()}, so ${countingSince} is only partly counted and earlier months have no figure.`}
					/>
				)}
			{neverActive && !loading ? (
				<Empty description="Nobody has received a token from this bucket yet. People are counted when an app signs them in or renews their tokens." />
			) : (
				<>
					<Row gutter={[16, 16]}>
						<Col
							xs={12}
							md={6}
						>
							<Card size="small">
								<Statistic
									title={shown?.final === false ? `${month} so far` : month}
									value={shown?.total ?? '—'}
									loading={loading}
								/>
								{shown && (
									<Tag color={shown.final ? undefined : 'blue'}>
										{shown.final ? 'Final' : 'Not final'}
									</Tag>
								)}
							</Card>
						</Col>
						<Col
							xs={12}
							md={6}
						>
							<Card size="small">
								<Statistic
									title={labels[1] ?? 'Previous month'}
									value={previous?.total ?? '—'}
									loading={loading}
								/>
							</Card>
						</Col>
						<Col
							xs={12}
							md={6}
						>
							<Card size="small">
								<Statistic
									title="Change"
									value={changeText(shown, previous) || '—'}
									loading={loading}
								/>
								{shown && !shown.final && (
									<Typography.Text type="secondary">
										month not final yet
									</Typography.Text>
								)}
							</Card>
						</Col>
						{month === thisMonth && (
							<Col
								xs={12}
								md={6}
							>
								<Card size="small">
									<Statistic
										title="Today so far (UTC)"
										value={today?.total ?? '—'}
										loading={loading}
									/>
								</Card>
							</Col>
						)}
					</Row>
					<Card
						size="small"
						title="Thirteen months"
						extra={viewSwitch}
					>
						{view === 'chart' ? (
							<>
								<MonthBars
									labels={[...labels].reverse()}
									sums={[...labels]
										.reverse()
										.map((l) => asSum(figureOf.get(l) ?? null))}
								/>
								<MonthLegend />
							</>
						) : (
							<Table
								size="small"
								pagination={false}
								rowKey="key"
								loading={loading}
								dataSource={monthRows}
								columns={[
									{
										title: 'Month',
										dataIndex: 'period',
										key: 'period',
										render: (period: string) => (
											<Button
												type="link"
												size="small"
												style={{ padding: 0 }}
												aria-pressed={period === month}
												onClick={() => choose(period)}
											>
												{period}
											</Button>
										)
									},
									...COLUMNS.map((c) => ({
										...c,
										render: (value: unknown, row: Partial<FigureRow>) =>
											row.status === undefined ? (
												<Typography.Text
													type="secondary"
													title="Not counted: the bucket didn't exist yet, or counting hadn't started"
												>
													—
												</Typography.Text>
											) : 'render' in c && c.render ? (
												c.render(value as FigureRow['status'])
											) : (
												String(value)
											)
									}))
								]}
								rowClassName={(row) =>
									row.period === month ? 'ant-table-row-selected' : ''
								}
							/>
						)}
					</Card>
					<Card
						size="small"
						title={`${month} by day${labels[1] ? `, over ${labels[1]}` : ''}`}
						extra={viewSwitch}
					>
						{view === 'chart' ? (
							<DayBars
								days={(read?.days ?? []).map((d) => d.total)}
								previousDays={previousDays.map((d) => d.total)}
								month={month}
								previousMonth={labels[1] ?? ''}
							/>
						) : (
							<Table
								size="small"
								pagination={false}
								rowKey="key"
								loading={loading}
								dataSource={(read?.days ?? []).map(figureRow)}
								columns={[
									{ title: 'Day', dataIndex: 'period', key: 'period' },
									...COLUMNS
								]}
							/>
						)}
					</Card>
				</>
			)}
			<Typography.Text type="secondary">
				People this bucket issued tokens to, counted once per month and once per
				day, in UTC. One person can appear under more than one kind, so the
				kinds add up to more than the total.
			</Typography.Text>
		</Flex>
	);
}
