import { useEffect, useState } from 'react';
import { Space, Tag, Typography } from 'antd';
import { PageHeader } from '../frame/PageHeader.js';
import { request } from '../frame/request.js';
import { Link } from '../frame/router.js';
import { bucketHref } from '../frame/routes.js';
import { ADMIN_BUCKET_ID, DEFAULT_BUCKET_ID } from '../../consts.js';
import { KeyCards, type Dependent } from './keys/KeyCards.js';
import type { BucketView } from './bucketView.js';

/*
 * The instance (root) signing keys: what the default bucket, the administrators and every bucket without an
 * address of its own sign with. The same cards as a bucket's keys; only a super administrator reaches this page.
 *
 * It names who depends on them (specs/086), from the bucket list a super administrator already reads in full,
 * because retiring a root key reaches every one of those relying parties at once.
 */
export function Keys() {
	const [dependents, setDependents] = useState<Dependent[] | null>(null);

	useEffect(() => {
		void (async () => {
			const result = await request<BucketView[]>('GET', '/admin/api/buckets');
			if (!result.ok) {
				setDependents([]);
				return;
			}
			setDependents(
				result.data
					.filter(
						(b) => b.addressForm === 'root' || b.addressForm === 'unaddressed'
					)
					.map((b) => ({
						id: b._id,
						name:
							b._id === DEFAULT_BUCKET_ID
								? 'Default bucket'
								: b._id === ADMIN_BUCKET_ID
									? 'Administrators'
									: b.name,
						href:
							b._id === ADMIN_BUCKET_ID
								? '/admin/administrators'
								: bucketHref(b._id)
					}))
			);
		})();
	}, []);

	return (
		<>
			<PageHeader title="Signing keys" />
			<Space
				orientation="vertical"
				style={{ width: '100%' }}
				size="middle"
			>
				{dependents !== null && (
					<Typography.Paragraph>
						Signs for the root issuer:{' '}
						{dependents.length === 0
							? 'no bucket is served at the root.'
							: dependents.map((d, i) => (
									<span key={d.id}>
										{i > 0 ? ', ' : ''}
										<Link href={d.href}>{d.name}</Link>
										{d.id === ADMIN_BUCKET_ID && (
											<Tag style={{ marginLeft: 4 }}>console sign-in</Tag>
										)}
									</span>
								))}
						.
					</Typography.Paragraph>
				)}
				<KeyCards
					base="/admin/api/jwks"
					keySetUrl={null}
					historyHref="/admin/audit?actionPrefix=jwks."
					canEdit
					dependents={dependents ?? []}
				/>
			</Space>
		</>
	);
}
