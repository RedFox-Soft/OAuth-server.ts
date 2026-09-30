import { Typography } from 'antd';
import { KeyLifecyclePanel } from './KeyLifecyclePanel.js';

/*
 * The instance (root) signing keys: what the default bucket, the administrators and every bucket without
 * an address of its own sign with. The same lifecycle as a bucket's keys, and the same panel; only a super
 * administrator reaches this page.
 */
export function Keys() {
	return (
		<>
			<Typography.Title
				level={4}
				style={{ margin: 0 }}
			>
				Signing keys
			</Typography.Title>
			<KeyLifecyclePanel
				base="/admin/api/jwks"
				title="Instance keys"
			/>
		</>
	);
}
