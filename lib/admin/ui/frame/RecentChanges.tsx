import { useEffect, useState, type ReactNode } from 'react';
import { Card, Flex, Skeleton, Space, Tag, Typography } from 'antd';
import { actorLabel, type AuditEntry } from './auditEntry.js';
import { request } from './request.js';
import { Link } from './router.js';

/*
 * The last few audit entries for one context — a bucket, a provisioning connection — where the question
 * "what changed here?" is asked (specs/085). One full audit UI stays the Audit page: "View all" opens it with
 * the same filters as removable chips.
 *
 * Fetched only when the caller may read the whole history it would show; a partial history that looks
 * complete is worse than none, so the cards are mounted for editors and super administrators only.
 */
export function RecentChanges({
	title,
	params,
	empty,
	extra
}: {
	title: string;
	/* The audit filters, as the Audit page's address carries them. */
	params: Record<string, string>;
	empty: string;
	extra?: ReactNode;
}) {
	const [entries, setEntries] = useState<AuditEntry[] | null>(null);
	const [failed, setFailed] = useState(false);
	const query = new URLSearchParams(params).toString();

	useEffect(() => {
		void (async () => {
			const result = await request<{ entries: AuditEntry[] }>(
				'GET',
				`/admin/api/audit?${query}&page=1&pageSize=5`
			);
			setFailed(!result.ok);
			setEntries(result.ok ? result.data.entries : []);
		})();
	}, [query]);

	return (
		<Card
			title={title}
			extra={
				<Space>
					{extra}
					<Link href={`/admin/audit?${query}`}>View all in Audit</Link>
				</Space>
			}
		>
			{failed ? (
				<Typography.Text type="secondary">
					The audit trail could not be read. Open it in Audit.
				</Typography.Text>
			) : (
				<Flex
					vertical
					gap={8}
				>
					{entries === null ? (
						<Skeleton
							active
							paragraph={{ rows: 2 }}
							title={false}
						/>
					) : entries.length === 0 ? (
						<Typography.Text type="secondary">{empty}</Typography.Text>
					) : (
						entries.map((entry) => (
							<Space
								key={entry._id}
								wrap
								size={6}
							>
								<Tag>{entry.action}</Tag>
								{entry.kid ? (
									<Typography.Text code>{entry.kid}</Typography.Text>
								) : null}
								<Typography.Text>{actorLabel(entry)}</Typography.Text>
								<Typography.Text type="secondary">
									{new Date(entry.timestamp).toLocaleString()}
								</Typography.Text>
							</Space>
						))
					)}
				</Flex>
			)}
		</Card>
	);
}
