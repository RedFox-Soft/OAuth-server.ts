import { useCallback, useEffect, useState } from 'react';
import { Flex, Table, Tag, Typography } from 'antd';
import { Link } from '../../frame/router.js';
import { request } from '../../frame/request.js';
import { EmptyState, LoadFailed } from '../../frame/states.js';

interface AuditEntry {
	_id: string;
	actorEmail: string;
	action: string;
	attributes: string[];
	viaSurface?: 'mcp' | 'scim' | 'upstream' | null;
	timestamp: string;
}

interface AuditPage {
	entries: AuditEntry[];
	total: number;
}

const SHOWN = 20;

/*
 * What administrators, agents and directories recently did to this person: the audit entries that name
 * them. Their own sign-ins are not recorded per person, so this is never a sign-in history, and it says so.
 * Changes to a group they are in are recorded against the group, and are found there.
 */
export function UserActivityTab({
	bucketId,
	userId
}: {
	bucketId: string;
	userId: string;
}) {
	const [page, setPage] = useState<AuditPage | null>(null);
	const [loadError, setLoadError] = useState<string | null>(null);
	const [loading, setLoading] = useState(true);
	const filter = new URLSearchParams({
		targetId: userId,
		targetScope: bucketId
	}).toString();

	const fetchEntries = useCallback(async () => {
		try {
			const result = await request<AuditPage>(
				'GET',
				`/admin/api/audit?${filter}&pageSize=${String(SHOWN)}`
			);
			if (result.ok) {
				setPage(result.data);
				setLoadError(null);
			} else {
				setLoadError(result.error.message);
			}
		} finally {
			setLoading(false);
		}
	}, [filter]);
	useEffect(() => {
		void fetchEntries();
	}, [fetchEntries]);

	if (loadError !== null) {
		return (
			<LoadFailed
				reason={loadError}
				onRetry={() => {
					setLoading(true);
					void fetchEntries();
				}}
			/>
		);
	}

	return (
		<Flex
			vertical
			gap={12}
		>
			<Flex
				justify="space-between"
				wrap
				gap={12}
			>
				<Typography.Text type="secondary">
					Sign-ins aren&apos;t recorded per person; this lists the changes made
					to them.
				</Typography.Text>
				<Link href={`/admin/audit?${filter}`}>Open in Audit</Link>
			</Flex>
			<Table<AuditEntry>
				rowKey="_id"
				size="small"
				loading={loading}
				dataSource={page?.entries ?? []}
				pagination={false}
				locale={{
					emptyText: (
						<EmptyState purpose="No administrative changes to this person yet." />
					)
				}}
				columns={[
					{
						title: 'When',
						dataIndex: 'timestamp',
						render: (at: string) => new Date(at).toLocaleString()
					},
					{ title: 'Action', dataIndex: 'action' },
					{
						title: 'Changed',
						dataIndex: 'attributes',
						render: (attributes: string[]) =>
							attributes.map((a) => <Tag key={a}>{a}</Tag>)
					},
					{
						title: 'By',
						key: 'by',
						render: (_: unknown, row: AuditEntry) => (
							<>
								{row.actorEmail}
								{row.viaSurface === 'mcp' && <Tag>agent</Tag>}
								{row.viaSurface === 'scim' && <Tag>directory</Tag>}
							</>
						)
					}
				]}
			/>
			{page && page.total > page.entries.length && (
				<Typography.Text type="secondary">
					The latest {String(page.entries.length)} of {String(page.total)} —
					open in Audit for the rest.
				</Typography.Text>
			)}
		</Flex>
	);
}
