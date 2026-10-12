import { useEffect, useState } from 'react';
import { Form, Select } from 'antd';
import type { UserBucket } from '../../../adapters/types.js';
import { ADMIN_BUCKET_ID, DEFAULT_BUCKET_ID } from '../../consts.js';
import { scopeOptionLabel, type ScopeOption } from '../pages/ScopeSwitcher.js';
import { request } from './request.js';

/*
 * The group a new project or bucket will belong to, chosen in the creation dialog (specs/087). Created in the
 * wrong group, a thing has to be moved, which is a previewed act; chosen here, it costs a click. The header's
 * current group is the default, so a dialog left alone creates exactly where it did before.
 *
 * Offered from the scope list — the groups the caller works in — and checked again by the server, which refuses
 * a group the caller may not create in.
 */
export function GroupField() {
	const form = Form.useFormInstance<{ groupId?: string }>();
	const [groups, setGroups] = useState<ScopeOption[] | null>(null);

	useEffect(() => {
		void (async () => {
			const result = await request<{
				activeGroupId: string;
				available: ScopeOption[];
			}>('GET', '/admin/api/scope');
			if (!result.ok) {
				setGroups([]);
				return;
			}
			setGroups(result.data.available);
			if (form.getFieldValue('groupId') === undefined) {
				form.setFieldValue('groupId', result.data.activeGroupId);
			}
		})();
	}, [form]);

	return (
		<Form.Item
			name="groupId"
			label="Group"
			extra="Its members manage it. You can move it to another group later."
			rules={[{ required: true, message: 'Choose a group' }]}
		>
			<Select<string>
				loading={groups === null}
				options={(groups ?? []).map((g) => ({
					value: g.id,
					label: scopeOptionLabel(g)
				}))}
			/>
		</Form.Item>
	);
}

/*
 * A new project's bucket, from the chosen group's own buckets (specs/087): a project and its bucket always
 * share a group. Left empty, the project uses the shared Default bucket, as before. Changing the group clears
 * a bucket that belonged to the previous one.
 */
export function BucketField() {
	const form = Form.useFormInstance<{ groupId?: string; bucketId?: string }>();
	const groupId = Form.useWatch<string | undefined>('groupId', form);
	const [buckets, setBuckets] = useState<UserBucket[] | null>(null);

	useEffect(() => {
		void (async () => {
			const result = await request<UserBucket[]>('GET', '/admin/api/buckets');
			setBuckets(result.ok ? result.data : []);
		})();
	}, []);

	const offered = (buckets ?? []).filter(
		(b) =>
			b.ownerGroupId === groupId &&
			b._id !== ADMIN_BUCKET_ID &&
			b._id !== DEFAULT_BUCKET_ID &&
			// Scheduled for deletion (specs/090): the server refuses a new project there.
			!b.deletion
	);

	useEffect(() => {
		const chosen = form.getFieldValue('bucketId') as string | undefined;
		if (chosen && !offered.some((b) => b._id === chosen)) {
			form.setFieldValue('bucketId', undefined);
		}
	});

	return (
		<Form.Item
			name="bucketId"
			label="Bucket"
			extra="Which people its applications sign in. Leave empty to use the shared Default bucket; you can choose one later in the project's Settings."
		>
			<Select<string>
				allowClear
				placeholder="Default bucket"
				loading={buckets === null}
				options={offered.map((b) => ({ value: b._id, label: b.name }))}
				notFoundContent="This group has no bucket yet."
			/>
		</Form.Item>
	);
}
