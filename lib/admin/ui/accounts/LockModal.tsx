import { useState } from 'react';
import { Form, Input, Modal, Typography } from 'antd';
import { request } from '../frame/request.js';
import { useFeedback } from '../frame/feedback.js';

/*
 * The reason is the confirmation: it is asked for because it is kept on the record, and typing it is a
 * deliberate act no stray click makes (user.lock is C1, inline).
 */
export function LockModal({
	account,
	url,
	onClose,
	onDone
}: {
	account: { email: string } | null;
	/* POST { reason }. */
	url: string;
	onClose: () => void;
	onDone: () => void;
}) {
	const [form] = Form.useForm<{ reason: string }>();
	const feedback = useFeedback();
	const [saving, setSaving] = useState(false);

	async function onFinish({ reason }: { reason: string }) {
		if (!account) return;
		setSaving(true);
		try {
			const result = await request('POST', url, { reason: reason.trim() });
			if (!result.ok) {
				feedback.failed(result, form);
				return;
			}
			feedback.done(`User ${account.email} locked.`);
			form.resetFields();
			onClose();
			onDone();
		} finally {
			setSaving(false);
		}
	}

	return (
		<Modal
			title={account ? `Lock ${account.email}` : 'Lock user'}
			open={account !== null}
			onCancel={onClose}
			onOk={() => form.submit()}
			okText="Lock"
			okButtonProps={{ danger: true }}
			confirmLoading={saving}
			destroyOnHidden
		>
			<Typography.Paragraph type="secondary">
				Their sessions and tokens end at once, and they cannot sign in until an
				administrator unlocks them — whatever a directory managing them sends.
			</Typography.Paragraph>
			<Form<{ reason: string }>
				form={form}
				layout="vertical"
				onFinish={(values) => void onFinish(values)}
				scrollToFirstError
			>
				<Form.Item
					name="reason"
					label="Reason"
					tooltip="Kept on the user's record, not in the audit trail, because it may name a person or an incident. Shown to whoever may unlock them."
					rules={[{ required: true, whitespace: true, max: 500 }]}
				>
					<Input.TextArea rows={3} />
				</Form.Item>
			</Form>
		</Modal>
	);
}
