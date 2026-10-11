import type { BucketView } from './bucketView.js';
import { KeyCards } from './keys/KeyCards.js';
import { RootKeysCard } from './keys/RootKeysCard.js';

/*
 * A bucket's Signing keys tab. Which variant it is comes from the bucket read (specs/086): a bucket with a
 * path or a hostname has keys of its own; one served at the root signs with the instance keys and is told so,
 * without first asking for keys the server would refuse with a 409.
 */
export function BucketKeysPanel({
	bucket,
	canEdit,
	superAdmin
}: {
	bucket: BucketView;
	/* False when the caller may read this bucket but not change it; the server would refuse every write. */
	canEdit: boolean;
	superAdmin: boolean;
}) {
	if (bucket.addressForm === 'root' || bucket.addressForm === 'unaddressed') {
		return (
			<RootKeysCard
				bucketId={bucket._id}
				bucketName={bucket.name}
				superAdmin={superAdmin}
			/>
		);
	}
	const id = encodeURIComponent(bucket._id);
	return (
		<KeyCards
			base={`/admin/api/buckets/${id}/keys`}
			keySetUrl={bucket.issuer ? `${bucket.issuer}/jwks` : null}
			historyHref={`/admin/audit?bucket=${id}&actionPrefix=bucket.key.`}
			canEdit={canEdit}
		/>
	);
}
