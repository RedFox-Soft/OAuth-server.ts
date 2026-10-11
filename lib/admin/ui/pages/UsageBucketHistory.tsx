import { useEffect, useState } from 'react';
import { Result, Skeleton, Tag } from 'antd';
import { PageHeader } from '../frame/PageHeader.js';
import { request } from '../frame/request.js';
import { Link, useNavigate, useRoute } from '../frame/router.js';
import { bucketHref, usageBucketHref } from '../frame/routes.js';
import { LoadFailed, NoAccess } from '../frame/states.js';
import {
	BucketActivityPanel,
	type BucketActivityRead
} from './BucketActivityPanel.js';

/*
 * A deleted bucket's usage history (specs/086), for a super administrator: a billing question about a tenant
 * that no longer exists needs a page that can be linked to. The bucket is gone, so the page belongs to Usage
 * and reads its tombstone through the activity route; a live bucket's history is its own Activity tab.
 */
export function UsageBucketHistory({ bucketId }: { bucketId: string }) {
	const navigate = useNavigate();
	const { query } = useRoute();
	const [read, setRead] = useState<BucketActivityRead | null>(null);
	const [status, setStatus] = useState<number | null>(null);
	const [attempt, setAttempt] = useState(0);

	useEffect(() => {
		void (async () => {
			const result = await request<BucketActivityRead>(
				'GET',
				`/admin/api/buckets/${encodeURIComponent(bucketId)}/activity`
			);
			if (!result.ok) {
				setStatus(result.status);
				return;
			}
			if (result.data.deletedAt === null) {
				// Still here: its history lives on its own Activity tab, at the same month.
				const month = query.get('month');
				void navigate(
					`${bucketHref(bucketId, 'activity')}${month ? `?month=${encodeURIComponent(month)}` : ''}`,
					{ replace: true }
				);
				return;
			}
			setRead(result.data);
		})();
	}, [bucketId, attempt, navigate, query]);

	if (status !== null) {
		return status === 403 || status === 404 ? (
			<NoAccess
				what="bucket"
				backHref="/admin/usage"
				backLabel="Back to Usage"
			/>
		) : (
			<LoadFailed
				onRetry={() => {
					setStatus(null);
					setAttempt((n) => n + 1);
				}}
			/>
		);
	}
	if (!read || read.deletedAt === null) return <Skeleton active />;

	return (
		<>
			<PageHeader
				crumbs={[
					{ label: 'Usage', href: '/admin/usage' },
					{ label: read.name }
				]}
				title={read.name}
				tags={<Tag color="red">Deleted</Tag>}
				meta={`Deleted on ${new Date(read.deletedAt).toLocaleDateString()}${read.lastOwner ? ` · last owned by ${read.lastOwner.label}` : ''}`}
			/>
			<BucketActivityPanel
				bucketId={bucketId}
				readOnly
			/>
		</>
	);
}

/*
 * A bucket address that answers no-access. For a super administrator, who may read a deleted bucket's figures,
 * it may be a bucket that was deleted: then it says when, and leads to its history (specs/086). Anyone else gets
 * the ordinary answer without that read, so whether a bucket ever existed is not revealed to them.
 */
export function BucketNotFound({
	bucketId,
	superAdmin
}: {
	bucketId: string;
	superAdmin: boolean;
}) {
	const [deletedAt, setDeletedAt] = useState<string | null>(null);

	useEffect(() => {
		if (!superAdmin) return;
		void (async () => {
			const result = await request<BucketActivityRead>(
				'GET',
				`/admin/api/buckets/${encodeURIComponent(bucketId)}/activity`
			);
			if (result.ok && result.data.deletedAt)
				setDeletedAt(result.data.deletedAt);
		})();
	}, [bucketId, superAdmin]);

	if (deletedAt === null) {
		return (
			<NoAccess
				what="bucket"
				backHref="/admin/buckets"
				backLabel="Back to Buckets"
			/>
		);
	}
	return (
		<Result
			status="404"
			title={`This bucket was deleted on ${new Date(deletedAt).toLocaleDateString()}`}
			extra={
				<Link href={usageBucketHref(bucketId)}>See its usage history</Link>
			}
		/>
	);
}
