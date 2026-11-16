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
	viaSurface?: 'mcp' | 'scim' | 'upstream' | 'self-service' | null;
	timestamp: string;
}

interface AuditPage {
	entries: AuditEntry[];
	total: number;
}

const SHOWN = 20;

/*
 * What administrators, agents, directories and the person themselves changed about this person: the audit entries
 * that name them, without the audited reads of their activity (`changesOnly`). What the person did is the Activity
 * tab. Changes to a group they are in are recorded against the group, and are found there.
 */
export function UserChangesTab({
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
		targetScope: bucketId,
		changesOnly: 'true'
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
					Changes made to this person by administrators, agents, directories and
					the person themselves. What they did is under Activity.
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
								{/* The person on their connected-apps page: the sentinel is not an address (specs/095). */}
								{row.viaSurface === 'self-service'
									? 'The person themselves'
									: row.actorEmail}
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
