import { useCallback, useState } from 'react';
import { Alert, Card } from 'antd';
import { KeyLifecyclePanel } from './KeyLifecyclePanel.js';

/*
 * A bucket's own signing keys, for a bucket with an address of its own. A bucket served at the root has no
 * keys of its own — the server answers 409 — and is sent to the instance key page instead.
 */
export function BucketKeysPanel({ bucketId }: { bucketId: string }) {
	const [rootServed, setRootServed] = useState(false);
	const onUnavailable = useCallback((status: number) => {
		setRootServed(status === 409);
	}, []);

	if (rootServed) {
		return (
			<Card
				title="Signing keys"
				style={{ marginTop: 24 }}
			>
				<Alert
					type="info"
					showIcon
					title="This bucket signs with the instance keys"
					description="It has no address of its own, so it shares the root issuer and its key set. Those keys are managed on the Keys page."
				/>
			</Card>
		);
	}

	return (
		<KeyLifecyclePanel
			base={`/admin/api/buckets/${bucketId}/keys`}
			title="Signing keys"
			onUnavailable={onUnavailable}
		/>
	);
}
