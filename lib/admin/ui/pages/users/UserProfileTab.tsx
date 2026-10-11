import { useState } from 'react';
import {
	Button,
	Card,
	Descriptions,
	Flex,
	Form,
	Input,
	Modal,
	Select,
	Space,
	Tag,
	Typography
} from 'antd';
import { bucketHref } from '../../frame/routes.js';
import { useNavigate } from '../../frame/router.js';
import { request } from '../../frame/request.js';
import { useFeedback } from '../../frame/feedback.js';
import { useConfirm } from '../../frame/confirm.js';
import type { BucketCan } from '../../frame/can.js';
import { ClaimsDrawer } from '../../accounts/ClaimsDrawer.js';
import type { BucketView } from '../bucketView.js';
import type { ConnectionView } from '../ProvisioningPanel.js';
import { nameOf, usersApi, type EndUser } from './endUser.js';
import { useUserActions } from './useUserActions.js';

interface AssignValues {
	connectionId: string;
	userName?: string;
	externalId?: string;
}

/* Whether the person can sign in now, and if not, every reason — the first question of an incident. */
function signInState(user: EndUser): { can: boolean; reasons: string[] } {
	const reasons: string[] = [];
	if (!user.active) reasons.push('deactivated');
	if (user.lockedLocally) {
		const lock = user.lockedLocally;
		const by = lock.byEmail
			? ` by ${lock.byEmail}`
			: lock.byEmail === null
				? ' by an administrator who no longer exists'
				: '';
		reasons.push(
			`locked${by} on ${new Date(lock.at).toLocaleString()}: ${lock.reason}`
		);
	}
	return { can: reasons.length === 0, reasons };
}

export function UserProfileTab({
	bucketId,
	bucket,
	user,
	can,
	connections,
	onChanged
}: {
	bucketId: string;
	bucket: BucketView;
	user: EndUser;
	can: BucketCan;
	connections: ConnectionView[];
	onChanged: () => void;
}) {
	const feedback = useFeedback();
	const confirm = useConfirm();
	const navigate = useNavigate();
	const actions = useUserActions(bucketId);
	const [claimsOpen, setClaimsOpen] = useState(false);
	const [emailOpen, setEmailOpen] = useState(false);
	const [assignOpen, setAssignOpen] = useState(false);
	const [resending, setResending] = useState(false);
	const [emailForm] = Form.useForm<{ email: string }>();
	const [assignForm] = Form.useForm<AssignValues>();

	const api = usersApi(bucketId, user._id);
	const local = !user.provisionedBy;
	const manage = can.manageUsers;
	const state = signInState(user);
	const name = nameOf(user);
	const connectionName = (id: string) =>
		connections.find((c) => c.id === id)?.displayName ?? id;

	/*
	 * The dialog steps aside while the question is asked, so no dialog opens on top of another, and comes
	 * back with what was typed when the server refuses the address — on its field.
	 */
	async function onChangeEmail({ email }: { email: string }) {
		setEmailOpen(false);
		const agreed = await confirm('user.email.change', {
			target: user.email,
			consequences: [
				`They sign in as ${email} from now on, and ${user.email} stops working.`,
				'The new address is unverified until they follow a verification message; one sent before now no longer counts.',
				'Nothing is sent to either address: resend verification when they expect it.'
			]
		});
		if (!agreed) return;
		const result = await request('POST', `${api}/email`, { email });
		if (!result.ok) {
			if (result.error.field === 'email') {
				setEmailOpen(true);
				emailForm.setFieldsValue({ email });
				emailForm.setFields([
					{ name: 'email', errors: [result.error.message] }
				]);
				return;
			}
			feedback.failed(result);
			return;
		}
		feedback.done(`Email of ${user.email} changed to ${email}.`);
		emailForm.resetFields();
		onChanged();
	}

	async function onResend() {
		setResending(true);
		try {
			await actions.resendVerification(user);
		} finally {
			setResending(false);
		}
	}

	async function onAssign(values: AssignValues) {
		const userName = values.userName?.trim();
		const externalId = values.externalId?.trim();
		const connection = connectionName(values.connectionId);
		setAssignOpen(false);
		const agreed = await confirm('user.connection.assign', {
			target: user.email,
			consequences: [
				`${connection} then owns this account: it is read-only here except for a local lock.`,
				'It cannot be handed back from the console.'
			]
		});
		if (!agreed) return;
		const result = await request('POST', `${api}/connection`, {
			connectionId: values.connectionId,
			...(userName ? { userName } : {}),
			...(externalId ? { externalId } : {})
		});
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done(`User ${user.email} handed over to ${connection}.`);
		assignForm.resetFields();
		onChanged();
	}

	async function onDelete() {
		if (await actions.remove(user)) {
			void navigate(bucketHref(bucketId, 'users'), { replace: true });
		}
	}

	const claims = Object.entries(user.claims ?? {});
	const mayAssign = can.edit && local && connections.length > 0;
	const mayDelete = manage && local;

	return (
		<Flex
			vertical
			gap={16}
		>
			<Card title="Account">
				<Descriptions
					column={1}
					size="small"
					items={[
						{
							key: 'signIn',
							label: 'Can sign in',
							children: state.can ? (
								'Yes'
							) : (
								<Typography.Text type="danger">
									No — {state.reasons.join('; ')}
								</Typography.Text>
							)
						},
						{
							key: 'email',
							label: 'Email',
							children: (
								<Space
									wrap
									size={8}
								>
									<Typography.Text copyable>{user.email}</Typography.Text>
									{user.verified ? (
										<Tag color="green">Verified</Tag>
									) : (
										<Tag color="orange">Unverified</Tag>
									)}
									{manage && !user.verified && (
										<Button
											size="small"
											loading={resending}
											onClick={() => void onResend()}
										>
											Resend verification
										</Button>
									)}
									{manage && local && (
										<Button
											size="small"
											onClick={() => {
												emailForm.setFieldsValue({ email: user.email });
												setEmailOpen(true);
											}}
										>
											Change email…
										</Button>
									)}
								</Space>
							)
						},
						...(name ? [{ key: 'name', label: 'Name', children: name }] : []),
						...(user.userName
							? [
									{
										key: 'userName',
										label: 'Username',
										children: user.userName
									}
								]
							: []),
						...(user.externalId
							? [
									{
										key: 'externalId',
										label: 'External ID',
										children: user.externalId
									}
								]
							: []),
						{
							key: 'managedBy',
							label: 'Managed by',
							children: user.provisionedBy
								? connectionName(user.provisionedBy)
								: 'This console'
						},
						...(bucket.emailVerificationRequired && !user.verified
							? [
									{
										key: 'verification',
										label: 'Verification',
										children:
											'This bucket requires a verified address: they are asked to verify when they next sign in.'
									}
								]
							: [])
					]}
				/>
			</Card>

			<Card
				title="Claims"
				extra={
					manage && local ? (
						<Button onClick={() => setClaimsOpen(true)}>Edit claims…</Button>
					) : undefined
				}
			>
				{claims.length === 0 ? (
					<Typography.Text type="secondary">
						No claims of their own. A client receives only the account's email
						and the claims the bucket's settings derive.
					</Typography.Text>
				) : (
					<Descriptions
						column={1}
						size="small"
						items={claims.map(([key, value]) => ({
							key,
							label: key,
							children:
								typeof value === 'string' ? value : JSON.stringify(value)
						}))}
					/>
				)}
			</Card>

			{(mayAssign || mayDelete) && (
				<Card
					title="Danger zone"
					styles={{ header: { color: 'var(--ant-color-error)' } }}
				>
					<Flex
						vertical
						gap={16}
					>
						{mayAssign && (
							<Flex
								justify="space-between"
								align="center"
								wrap
								gap={12}
							>
								<div>
									<Typography.Text strong>
										Hand over to a connection
									</Typography.Text>
									<br />
									<Typography.Text type="secondary">
										The directory then owns this person; it cannot be handed
										back from the console.
									</Typography.Text>
								</div>
								<Button
									danger
									onClick={() => {
										assignForm.resetFields();
										setAssignOpen(true);
									}}
								>
									Hand over…
								</Button>
							</Flex>
						)}
						{mayDelete && (
							<Flex
								justify="space-between"
								align="center"
								wrap
								gap={12}
							>
								<div>
									<Typography.Text strong>Delete user</Typography.Text>
									<br />
									<Typography.Text type="secondary">
										The account, its sessions, consents and tokens are
										destroyed.
									</Typography.Text>
								</div>
								<Button
									danger
									onClick={() => void onDelete()}
								>
									Delete user…
								</Button>
							</Flex>
						)}
					</Flex>
				</Card>
			)}

			<ClaimsDrawer
				account={user}
				url={api}
				open={claimsOpen}
				onClose={() => setClaimsOpen(false)}
				onDone={onChanged}
			/>

			<Modal
				title={`Change the email of ${user.email}`}
				open={emailOpen}
				onCancel={() => setEmailOpen(false)}
				onOk={() => emailForm.submit()}
				okText="Continue"
			>
				<Form<{ email: string }>
					form={emailForm}
					layout="vertical"
					onFinish={(values) => void onChangeEmail(values)}
				>
					<Form.Item
						name="email"
						label="New email"
						rules={[
							{ required: true, type: 'email' },
							{
								validator: async (_rule, value: string | undefined) => {
									if (value?.trim().toLowerCase() === user.email) {
										throw new Error('that is their address already');
									}
								}
							}
						]}
					>
						<Input autoComplete="off" />
					</Form.Item>
				</Form>
			</Modal>

			<Modal
				title={`Hand ${user.email} over to a connection`}
				open={assignOpen}
				onCancel={() => setAssignOpen(false)}
				onOk={() => assignForm.submit()}
				okText="Continue"
				destroyOnHidden
			>
				<Typography.Paragraph type="secondary">
					The directory then owns this account: it is read-only here except for
					a local lock. Give the names the directory knows this person by, so
					its next sync matches them instead of creating someone new.
				</Typography.Paragraph>
				<Form<AssignValues>
					form={assignForm}
					layout="vertical"
					onFinish={(values) => void onAssign(values)}
					scrollToFirstError
				>
					<Form.Item
						name="connectionId"
						label="Connection"
						rules={[{ required: true }]}
					>
						<Select
							options={connections.map((c) => ({
								label: c.displayName,
								value: c.id
							}))}
						/>
					</Form.Item>
					<Form.Item
						name="userName"
						label="userName"
					>
						<Input autoComplete="off" />
					</Form.Item>
					<Form.Item
						name="externalId"
						label="externalId"
						dependencies={['userName']}
						rules={[
							({ getFieldValue }) => ({
								validator: async (_rule, value: string | undefined) => {
									const userName = (
										getFieldValue('userName') as string | undefined
									)?.trim();
									if (!userName && !value?.trim()) {
										throw new Error('give a userName, an externalId, or both');
									}
								}
							})
						]}
					>
						<Input autoComplete="off" />
					</Form.Item>
				</Form>
			</Modal>
		</Flex>
	);
}
