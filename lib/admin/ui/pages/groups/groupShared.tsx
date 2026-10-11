import { useCallback, useState } from 'react';
import { Alert, Form, Input, Modal } from 'antd';
import { request } from '../../frame/request.js';
import { useFeedback } from '../../frame/feedback.js';
import { useConfirm } from '../../frame/confirm.js';

/* What `GET …/groups` answers for each group. */
export interface GroupView {
	id: string;
	displayName: string;
	externalId?: string;
	provisionedBy?: string;
	memberCount: number;
}

export function groupsApi(bucketId: string, groupId?: string): string {
	const base = `/admin/api/buckets/${encodeURIComponent(bucketId)}/groups`;
	return groupId === undefined
		? base
		: `${base}/${encodeURIComponent(groupId)}`;
}

/*
 * Renaming a group, with what it does to applications said as soon as the name differs (specs/084 US7).
 * Applications receive group *names* in the `groups` claim, so a rename is an authorization change for every
 * app that checks the old name. The form is the confirmation: there is no second question after it.
 */
export function RenameGroupModal({
	bucketId,
	group,
	onClose,
	onRenamed
}: {
	bucketId: string;
	group: GroupView | null;
	onClose: () => void;
	onRenamed: () => void;
}) {
	const feedback = useFeedback();
	const [form] = Form.useForm<{ displayName: string }>();
	const typed = Form.useWatch('displayName', form);
	const [saving, setSaving] = useState(false);
	const next = (typed as string | undefined)?.trim() ?? '';
	const changed = group !== null && next !== '' && next !== group.displayName;

	async function submit({ displayName }: { displayName: string }) {
		if (!group) return;
		setSaving(true);
		try {
			const result = await request('PATCH', groupsApi(bucketId, group.id), {
				displayName: displayName.trim()
			});
			if (!result.ok) {
				feedback.failed(result, form);
				return;
			}
			feedback.done(
				`User group ${group.displayName} renamed to ${displayName.trim()}.`
			);
			onRenamed();
			onClose();
		} finally {
			setSaving(false);
		}
	}

	return (
		<Modal
			title="Rename user group"
			open={group !== null}
			okText="Rename"
			okButtonProps={{ disabled: !changed }}
			confirmLoading={saving}
			onCancel={onClose}
			onOk={() => form.submit()}
			destroyOnHidden
		>
			<Form<{ displayName: string }>
				form={form}
				layout="vertical"
				initialValues={{ displayName: group?.displayName }}
				onFinish={(v) => void submit(v)}
			>
				<Form.Item
					name="displayName"
					label="Name"
					rules={[{ required: true, whitespace: true }]}
				>
					<Input autoComplete="off" />
				</Form.Item>
			</Form>
			{changed && (
				<Alert
					type="warning"
					showIcon
					title="Applications see the new name"
					description={`Apps that check for “${group.displayName}” will see “${next}” after each person's next sign-in or token refresh.`}
				/>
			)}
		</Modal>
	);
}

/* Deleting a group, asked with how many people lose what applications grant for it. */
export function useDeleteGroup(bucketId: string) {
	const feedback = useFeedback();
	const confirm = useConfirm();
	return useCallback(
		async (group: GroupView): Promise<boolean> => {
			const count = group.memberCount;
			if (
				!(await confirm('userGroup.delete', {
					target: group.displayName,
					consequences: [
						`Its ${String(count)} ${count === 1 ? 'member loses' : 'members lose'} whatever applications grant for it.`,
						'The people themselves are kept.'
					]
				}))
			) {
				return false;
			}
			const result = await request('DELETE', groupsApi(bucketId, group.id));
			if (!result.ok) {
				feedback.failed(result);
				return false;
			}
			feedback.done(`User group ${group.displayName} deleted.`);
			return true;
		},
		[bucketId, confirm, feedback]
	);
}
