import { useCallback, useEffect, useState } from 'react';
import { Alert, Card, Col, Row, Statistic, Table, Tag, Typography } from 'antd';
import { readJson } from '../json.js';
import {
	figureRow,
	type BucketActivityView,
	type FigureRow
} from '../activity/model.js';

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
	const [month, setMonth] = useState<string | undefined>(undefined);
	const [view, setView] = useState<BucketActivityView | null>(null);
	const [refusal, setRefusal] = useState<string | null>(null);

	const [loading, setLoading] = useState(true);

	// Every state write follows an await, so the effect below sets nothing synchronously.
	const fetchView = useCallback(
		async (id: string, asked: string | undefined) => {
			try {
				const query = asked ? `?month=${encodeURIComponent(asked)}` : '';
				const res = await fetch(
					`/admin/api/buckets/${encodeURIComponent(id)}/activity${query}`
				);
				const body = await readJson<BucketActivityView & { message?: string }>(
					res
				);
				setView(res.ok ? body : null);
				setRefusal(res.ok ? null : (body.message ?? 'unavailable'));
			} finally {
				setLoading(false);
			}
		},
		[]
	);

	useEffect(() => {
		void fetchView(bucketId, month);
	}, [fetchView, bucketId, month]);

	if (refusal !== null) {
		return (
			<Card
				title="Active users"
				style={{ marginTop: 24 }}
			>
				<Alert
					type="info"
					showIcon
					title="Usage is shown to the group that owns this bucket"
					description={refusal}
				/>
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
				columns={COLUMNS}
				dataSource={(view?.months ?? []).map(figureRow)}
				onRow={(row) => ({
					onClick: () => setMonth(row.period),
					style: { cursor: 'pointer' }
				})}
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
				columns={COLUMNS}
				dataSource={(view?.days ?? []).map(figureRow)}
			/>
		</Card>
	);
}
