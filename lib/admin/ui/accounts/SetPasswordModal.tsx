import { Checkbox, Form, Input, Modal } from 'antd';
import { request } from '../frame/request.js';
import { useFeedback } from '../frame/feedback.js';
import { useConfirm } from '../frame/confirm.js';

interface Values {
	password: string;
	signOut?: boolean;
}

/*
 * Setting somebody else's password, and optionally ending their sessions in the same request (specs/082
 * FR-010): two requests could leave the password changed and a stolen session still open.
 *
 * The password is typed in the dialog, which closes before the question is asked: a confirmation on top
 * of a dialog is a second modal the operator has to read through the first.
 */
export function SetPasswordModal({
	account,
	url,
	onClose,
	onDone
}: {
	account: { email: string } | null;
	/* The route that sets it: POST { password, signOut }. */
	url: string;
	onClose: () => void;
	onDone: () => void;
}) {
	const [form] = Form.useForm<Values>();
	const feedback = useFeedback();
	const confirm = useConfirm();

	async function onFinish({ password, signOut }: Values) {
		if (!account) return;
		onClose();
		form.resetFields();
		const agreed = await confirm('user.password.set', {
			target: account.email,
			consequences: [
				'The password they use now stops working.',
				'Whoever is told the new one can sign in as them.',
				signOut
					? 'Every session and token they hold ends now.'
					: 'Sessions they already have stay open.'
			]
		});
		if (!agreed) return;
		const result = await request('POST', url, {
			password,
			signOut: signOut === true
		});
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done(
			signOut
				? `New password set for ${account.email}, and they were signed out everywhere.`
				: `New password set for ${account.email}.`
		);
		onDone();
	}

	return (
		<Modal
			title={account ? `Set password for ${account.email}` : 'Set password'}
			open={account !== null}
			onCancel={onClose}
			onOk={() => form.submit()}
			okText="Continue"
			destroyOnHidden
		>
			<Form<Values>
				form={form}
				layout="vertical"
				onFinish={(values) => void onFinish(values)}
				scrollToFirstError
			>
				<Form.Item
					name="password"
					label="New password"
					rules={[{ required: true, min: 8 }]}
				>
					{/* This sets somebody else's password, so a stored one is never the right value. */}
					<Input.Password autoComplete="new-password" />
				</Form.Item>
				<Form.Item
					name="signOut"
					valuePropName="checked"
					extra="Use this when the password may have been known to someone else."
				>
					<Checkbox>Also sign out everywhere</Checkbox>
				</Form.Item>
			</Form>
		</Modal>
	);
}
