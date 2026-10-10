import { useCallback, useEffect, useState } from 'react';
import { Alert, Card, Input, Space, Table, Tag, Typography } from 'antd';
import { readJson } from '../json.js';
import {
	figureText,
	type OverviewRowView,
	type OverviewView
} from '../activity/model.js';

/*
 * Every bucket's active users on one page, for a super administrator (specs/076): the reserved buckets the
 * bucket list leaves out, and deleted buckets, whose history outlives them.
 */
export function Usage() {
	const [month, setMonth] = useState('');
	const [view, setView] = useState<OverviewView | null>(null);
	const [refusal, setRefusal] = useState<string | null>(null);

	const [loading, setLoading] = useState(true);

	// Every state write follows an await, so the effect below sets nothing synchronously.
	const fetchView = useCallback(async (asked: string) => {
		try {
			const query = asked ? `?month=${encodeURIComponent(asked)}` : '';
			const res = await fetch(`/admin/api/activity${query}`);
			const body = await readJson<OverviewView & { message?: string }>(res);
			setView(res.ok ? body : null);
			setRefusal(res.ok ? null : (body.message ?? 'unavailable'));
		} finally {
			setLoading(false);
		}
	}, []);

	useEffect(() => {
		void fetchView(month);
	}, [fetchView, month]);

	const columns = [
		{
			title: 'Bucket',
			key: 'name',
			render: (_: unknown, row: OverviewRowView) => (
				<Space>
					<span>{row.name}</span>
					{row.reserved ? <Tag>{row.reserved}</Tag> : null}
					{row.deleted ? <Tag color="red">deleted</Tag> : null}
				</Space>
			)
		},
		{
			title: view ? view.month : 'This month',
			key: 'current',
			render: (_: unknown, row: OverviewRowView) => figureText(row.current)
		},
		{
			title: view ? view.previous : 'Previous month',
			key: 'previous',
			render: (_: unknown, row: OverviewRowView) => figureText(row.previous)
		}
	];

	return (
		<Card>
			<Space
				orientation="vertical"
				style={{ width: '100%' }}
				size="middle"
			>
				<Typography.Title level={3}>Usage</Typography.Title>
				<Typography.Paragraph type="secondary">
					Monthly active users of every bucket: the people each one issued
					tokens to, counted once per month in UTC. A month in progress reads
					&quot;so far&quot;.
				</Typography.Paragraph>
				<Input.Search
					placeholder="YYYY-MM (this month when empty)"
					allowClear
					style={{ maxWidth: 320 }}
					onSearch={(value) => setMonth(value.trim())}
				/>
				{refusal !== null ? (
					<Alert
						type="error"
						showIcon
						title={refusal}
					/>
				) : null}
				<Table
					rowKey="bucketId"
					loading={loading}
					pagination={false}
					columns={columns}
					dataSource={view?.buckets ?? []}
				/>
			</Space>
		</Card>
	);
}
