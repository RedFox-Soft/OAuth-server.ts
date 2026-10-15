import { useEffect, useState } from 'react';
import { Form, Select } from 'antd';
import type { UserBucket } from '../../../adapters/types.js';
import { ADMIN_BUCKET_ID, DEFAULT_BUCKET_ID } from '../../consts.js';
import { scopeOptionLabel, type ScopeOption } from '../pages/ScopeSwitcher.js';
import { request } from './request.js';
import { meCan, useMe } from './me.js';

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

/* The bucket choice that stands for "create one now, named after the project" (specs/098). */
export const NEW_BUCKET = '__new__';

/*
 * A new project's bucket, from the chosen group's own buckets (specs/087): a project and its bucket always
 * share a group. Required (specs/098) — a project left without one used to sign people into the shared
 * Default bucket — so a group with no bucket yet is offered one created in the same step rather than a dead
 * end, and only a super administrator is offered the Default bucket. Changing the group clears a bucket that
 * belonged to the previous one.
 *
 * `created` is a bucket this dialog already made on an earlier attempt, kept selectable so a retry after a
 * refused project uses it instead of making a second.
 */
export function BucketField({
	created = null
}: {
	created?: Pick<UserBucket, '_id' | 'name' | 'ownerGroupId'> | null;
}) {
	const form = Form.useFormInstance<{ groupId?: string; bucketId?: string }>();
	const groupId = Form.useWatch<string | undefined>('groupId', form);
	const bucketId = Form.useWatch<string | undefined>('bucketId', form);
	const { me } = useMe();
	const can = meCan(me);
	const [buckets, setBuckets] = useState<UserBucket[] | null>(null);

	useEffect(() => {
		void (async () => {
			const result = await request<UserBucket[]>('GET', '/admin/api/buckets');
			setBuckets(result.ok ? result.data : []);
		})();
	}, []);

	const known = [
		...(buckets ?? []),
		...(created && !(buckets ?? []).some((b) => b._id === created._id)
			? [created]
			: [])
	];
	const owned = known.filter(
		(b) =>
			b.ownerGroupId === groupId &&
			b._id !== ADMIN_BUCKET_ID &&
			b._id !== DEFAULT_BUCKET_ID &&
			// Scheduled for deletion (specs/090): the server refuses a new project there.
			!('deletion' in b && b.deletion)
	);
	const options = [
		...owned.map((b) => ({ value: b._id, label: b.name })),
		...(can.instance
			? [{ value: DEFAULT_BUCKET_ID, label: 'Default bucket (shared)' }]
			: []),
		...(can.createBucket
			? [{ value: NEW_BUCKET, label: 'Create a new bucket' }]
			: [])
	];

	useEffect(() => {
		if (buckets === null) return;
		if (bucketId && !options.some((o) => o.value === bucketId)) {
			form.setFieldValue('bucketId', undefined);
		}
		// A group with nothing to choose from starts on the one way forward.
		if (
			!form.getFieldValue('bucketId') &&
			owned.length === 0 &&
			can.createBucket
		) {
			form.setFieldValue('bucketId', NEW_BUCKET);
		}
	});

	return (
		<Form.Item
			name="bucketId"
			label="Bucket"
			extra={
				bucketId === NEW_BUCKET
					? "A bucket of this group is created with the project, under the project's name and slug."
					: "Which people its applications sign in. You can change it later in the project's Settings."
			}
			rules={[{ required: true, message: 'Choose a bucket' }]}
		>
			<Select<string>
				placeholder="Choose a bucket"
				loading={buckets === null}
				options={options}
			/>
		</Form.Item>
	);
}
