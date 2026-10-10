import { useCallback, useEffect, useState } from 'react';
import { Alert, Card, Col, Row, Statistic, Table, Tag, Typography } from 'antd';
import { request } from '../frame/request.js';
import { EmptyState, LoadFailed } from '../frame/states.js';
import {
	figureRow,
	type BucketActivityView,
	type FigureRow
} from '../activity/model.js';
import { Link, useRoute } from '../frame/router.js';

/*
 * A bucket's monthly and daily active users (specs/076): the people it issued tokens to, counted once per
 * month and once per day. Counts only — the server never says who.
 */
const COLUMNS = [
	{ title: 'Period', dataIndex: 'period', key: 'period' },
	{
		title: 'Status',
		dataIndex: 'status',
		key: 'status',
		render: (status: FigureRow['status']) =>
			status === 'final' ? <Tag>final</Tag> : <Tag color="blue">not final</Tag>
	},
	{ title: 'Active users', dataIndex: 'total', key: 'total' },
	{ title: 'Local sign-in', dataIndex: 'local', key: 'local' },
	{ title: 'Upstream sign-in', dataIndex: 'upstream', key: 'upstream' },
	{ title: 'Renewal', dataIndex: 'renewal', key: 'renewal' },
	{ title: 'Provisioned', dataIndex: 'provisioned', key: 'provisioned' }
];

export function BucketActivityPanel({ bucketId }: { bucketId: string }) {
	/*
	 * The month is part of the address (`?month=`), so a month an operator is looking at can be linked to
	 * and survives a reload. Picking another replaces the address rather than adding to the history: Back
	 * leaves the tab instead of stepping through every month looked at.
	 */
	const { location, query } = useRoute();
	const month = query.get('month') ?? undefined;
	const monthHref = (period: string) =>
		`${location.pathname}?month=${encodeURIComponent(period)}`;
	const columns = [
		{
			...COLUMNS[0],
			render: (period: string) => (
				<Link
					href={monthHref(period)}
					replace
				>
					{period}
				</Link>
			)
		},
		...COLUMNS.slice(1)
	];
	const [view, setView] = useState<BucketActivityView | null>(null);
	/*
	 * Two different answers kept apart: a 403 is the rule (only the owning group sees usage), anything else
	 * is a read that failed and can be tried again.
	 */
	const [refusal, setRefusal] = useState<string | null>(null);
	const [failure, setFailure] = useState<string | null>(null);

	const [loading, setLoading] = useState(true);

	// Every state write follows an await, so the effect below sets nothing synchronously.
	const fetchView = useCallback(
		async (id: string, asked: string | undefined) => {
			try {
				const query = asked ? `?month=${encodeURIComponent(asked)}` : '';
				const result = await request<BucketActivityView>(
					'GET',
					`/admin/api/buckets/${encodeURIComponent(id)}/activity${query}`
				);
				setView(result.ok ? result.data : null);
				setRefusal(
					!result.ok && result.status === 403 ? result.error.message : null
				);
				setFailure(
					!result.ok && result.status !== 403 ? result.error.message : null
				);
			} finally {
				setLoading(false);
			}
		},
		[]
	);

	useEffect(() => {
		void fetchView(bucketId, month);
	}, [fetchView, bucketId, month]);

	if (refusal !== null || failure !== null) {
		return (
			<Card
				title="Active users"
				style={{ marginTop: 24 }}
			>
				{refusal !== null ? (
					<Alert
						type="info"
						showIcon
						title="Usage is shown to the group that owns this bucket"
						description={refusal}
					/>
				) : (
					<LoadFailed
						reason={failure ?? undefined}
						onRetry={() => {
							setLoading(true);
							void fetchView(bucketId, month);
						}}
					/>
				)}
			</Card>
		);
	}

	const shown = view?.month ?? null;
	const previous = view?.months[1] ?? null;

	return (
		<Card
			title="Active users"
			style={{ marginTop: 24 }}
		>
			<Typography.Paragraph type="secondary">
				People this bucket issued tokens to, each counted once per month and
				once per day, in UTC. A month in progress is not final until it ends.
			</Typography.Paragraph>
			<Row gutter={16}>
				<Col span={8}>
					<Card size="small">
						<Statistic
							title={
								shown?.final === false
									? `${shown.period} so far`
									: (shown?.period ?? 'This month')
							}
							value={shown?.total ?? '—'}
						/>
					</Card>
				</Col>
				<Col span={8}>
					<Card size="small">
						<Statistic
							title={previous?.period ?? 'Previous month'}
							value={previous?.total ?? '—'}
						/>
					</Card>
				</Col>
			</Row>
			<Typography.Title
				level={5}
				style={{ marginTop: 16 }}
			>
				By month
			</Typography.Title>
			<Table
				size="small"
				pagination={false}
				rowKey="key"
				loading={loading}
				columns={columns}
				dataSource={(view?.months ?? []).map(figureRow)}
				locale={{
					emptyText: (
						<EmptyState purpose="Nobody has been issued a token from this bucket yet." />
					)
				}}
			/>
			<Typography.Title
				level={5}
				style={{ marginTop: 16 }}
			>
				By day{shown ? `, ${shown.period}` : ''}
			</Typography.Title>
			<Table
				size="small"
				pagination={false}
				rowKey="key"
				loading={loading}
				columns={COLUMNS}
				dataSource={(view?.days ?? []).map(figureRow)}
				locale={{
					emptyText: (
						<EmptyState purpose="Nobody was issued a token from this bucket on any day of this month." />
					)
				}}
			/>
		</Card>
	);
}
