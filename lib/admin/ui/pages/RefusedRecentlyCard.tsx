import { Fragment, useCallback, useEffect, useState } from 'react';
import { Button, Card, Divider, Flex, Typography } from 'antd';
import { Link } from '../frame/router.js';
import { request } from '../frame/request.js';
import { LoadFailed } from '../frame/states.js';
import { userHref } from '../frame/routes.js';

/*
 * "Refused recently" (specs/134 contracts/console.md, У7): who this app or API refused, or asked to sign in again, in
 * the last day, on the Access tab where the administrator who just narrowed a rule is standing. Opening it is an
 * audited read, once per reader and day; the list comes from what the server recorded, up to a minute late.
 */

interface RefusalRow {
	accountId: string;
	email: string | null;
	outcome: 'refused' | 'sign_in_again';
	outcomeWords: string;
	reason: string;
	rule: string | null;
	tool: string | null;
	count: number;
	lastAt: string;
}

interface RefusalsView {
	asOf: string;
	accessSavedAt: string | null;
	cut: boolean;
	rows: RefusalRow[];
}

function timeWords(at: string): string {
	return new Date(at).toLocaleString(undefined, {
		day: 'numeric',
		month: 'short',
		hour: '2-digit',
		minute: '2-digit'
	});
}

function clockWords(at: string): string {
	return new Date(at).toLocaleTimeString(undefined, {
		hour: '2-digit',
		minute: '2-digit'
	});
}

export function RefusedRecentlyCard({
	bucketId,
	path
}: {
	bucketId: string;
	/* The read: `…/behind-proxy/:appId/refusals` or `…/resources/:resourceId/refusals`. */
	path: string;
}) {
	const [view, setView] = useState<RefusalsView | null>(null);
	const [failed, setFailed] = useState<string | null>(null);
	const [loading, setLoading] = useState(true);

	// Every state write follows an await, so the effect below calls this without setting `loading` first.
	const load = useCallback(async () => {
		try {
			const result = await request<RefusalsView>('POST', path, {});
			if (result.ok) {
				setView(result.data);
				setFailed(null);
			} else {
				setFailed(result.error.message);
			}
		} finally {
			setLoading(false);
		}
	}, [path]);

	useEffect(() => {
		void load();
	}, [load]);

	const savedAt = view?.accessSavedAt ?? null;
	const windowStart = view
		? new Date(view.asOf).getTime() - 24 * 60 * 60 * 1000
		: 0;
	const divideAt =
		savedAt !== null && new Date(savedAt).getTime() >= windowStart
			? savedAt
			: null;
	const firstBefore =
		divideAt === null || !view
			? -1
			: view.rows.findIndex((row) => row.lastAt <= divideAt);

	return (
		<Card
			title="Refused recently"
			extra={
				<Button
					size="small"
					loading={loading}
					onClick={() => {
						setLoading(true);
						void load();
					}}
				>
					Refresh
				</Button>
			}
		>
			{failed !== null && (
				<LoadFailed
					reason={failed}
					onRetry={() => void load()}
				/>
			)}
			{view && (
				<Flex
					vertical
					gap={8}
				>
					<Typography.Text type="secondary">
						As of {clockWords(view.asOf)}. Recorded up to a minute late.
					</Typography.Text>
					{view.rows.length === 0 ? (
						<Typography.Text>
							Nobody was refused in the last 24 hours. People who haven’t come
							back since you saved aren’t here yet: use Check access to see what
							a person would get.
						</Typography.Text>
					) : (
						view.rows.map((row, index) => (
							<Fragment
								key={`${row.accountId}-${row.outcome}-${row.reason}-${row.rule ?? ''}-${row.tool ?? ''}`}
							>
								{index === firstBefore && divideAt !== null && (
									<Divider plain>
										You saved these rules at {clockWords(divideAt)}
									</Divider>
								)}
								<Flex
									gap={8}
									wrap
									align="baseline"
								>
									<Link href={userHref(bucketId, row.accountId, 'activity')}>
										{row.email ?? 'A person no longer here'}
									</Link>
									<Typography.Text strong>{row.outcomeWords}</Typography.Text>
									<Typography.Text>{row.reason}</Typography.Text>
									{row.count > 1 && (
										<Typography.Text type="secondary">
											{row.count} times
										</Typography.Text>
									)}
									<Typography.Text type="secondary">
										last {timeWords(row.lastAt)}
									</Typography.Text>
								</Flex>
							</Fragment>
						))
					)}
					{divideAt !== null && view.rows.length > 0 && firstBefore === -1 && (
						<Divider plain>
							You saved these rules at {clockWords(divideAt)}
						</Divider>
					)}
					{view.cut && (
						<Typography.Text type="secondary">
							Showing the latest 100.
						</Typography.Text>
					)}
				</Flex>
			)}
		</Card>
	);
}
