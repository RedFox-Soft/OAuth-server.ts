import { useCallback, useEffect, useState } from 'react';
import { Table, Alert, Button, Modal, Form, Input, Space, Tag } from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import type { User } from '../../../adapters/types.js';
import { PageHeader } from '../frame/PageHeader.js';
import { request } from '../frame/request.js';
import { useFeedback } from '../frame/feedback.js';
import { useConfirm } from '../frame/confirm.js';
import { RowActions } from '../frame/RowActions.js';
import { LoadFailed } from '../frame/states.js';

/* What the list answers: the account without its password, and whether it holds the instance privilege. */
type AdminUser = Pick<User, '_id' | 'email' | 'active' | 'verified'> & {
	superAdmin: boolean;
};

interface CreateAdminValues {
	email: string;
	password: string;
}

export function Admins({
	onOpenSignInPolicy
}: {
	onOpenSignInPolicy?: () => void;
} = {}) {
	const feedback = useFeedback();
	const confirm = useConfirm();
	const [admins, setAdmins] = useState<AdminUser[]>([]);
	const [loading, setLoading] = useState(true);
	const [failed, setFailed] = useState<string | null>(null);
	const [open, setOpen] = useState(false);
	const [creating, setCreating] = useState(false);
	const [form] = Form.useForm<CreateAdminValues>();
	const [editingEmail, setEditingEmail] = useState<AdminUser | null>(null);
	const [emailForm] = Form.useForm<{ email: string }>();

	// Every state write follows an await, so the mount effect calls this without setting
	// `loading` first; `load` is the reload, which does.
	const fetchAdmins = useCallback(async () => {
		try {
			const result = await request<AdminUser[]>('GET', '/admin/api/admins');
			if (!result.ok) {
				setFailed(result.error.message);
				return;
			}
			setFailed(null);
			setAdmins(result.data);
		} finally {
			setLoading(false);
		}
	}, []);
	function load() {
		setLoading(true);
		return fetchAdmins();
	}

	useEffect(() => {
		void fetchAdmins();
	}, [fetchAdmins]);

	/*
	 * The instance privilege is granted and withdrawn by operations of its own, never by an account edit, and
	 * the server refuses withdrawing it from the last active super administrator — its reason is shown as is.
	 */
	async function onSetSuperAdmin(target: AdminUser, next: boolean) {
		const yes = next
			? await confirm('admin.superAdmin.grant', {
					target: target.email,
					consequences: [
						'They gain authority over every group, setting and key of this instance.'
					]
				})
			: await confirm('admin.superAdmin.withdraw', {
					target: target.email,
					consequences: [
						'They keep their groups but lose authority over the whole instance.'
					]
				});
		if (!yes) return;
		const result = await request(
			next ? 'POST' : 'DELETE',
			`/admin/api/admins/${encodeURIComponent(target._id)}/super-admin`
		);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done(
			next
				? `Super administration granted to ${target.email}.`
				: `Super administration withdrawn from ${target.email}.`
		);
		await load();
	}

	function openEmail(target: AdminUser, email: string) {
		emailForm.setFields([{ name: 'email', value: email, errors: [] }]);
		setEditingEmail(target);
	}

	/*
	 * Corrects an administrator's address. The server leaves the account unverified at the new one and
	 * refuses changing your own while administrators must verify theirs; either refusal is shown as is.
	 *
	 * The question is asked with the form closed — never a dialog over a dialog — and the form comes back
	 * with what was typed if the answer is no or the server refuses.
	 */
	async function onChangeEmail(target: AdminUser, email: string) {
		setEditingEmail(null);
		if (email === target.email) return;
		const yes = await confirm('admin.email.change', {
			target: target.email,
			consequences: [
				`They sign in as ${email} from now on; ${target.email} stops working.`,
				'If administrators must verify their email, they cannot sign in until they verify the new address.'
			]
		});
		if (!yes) {
			openEmail(target, email);
			return;
		}
		const result = await request(
			'PATCH',
			`/admin/api/admins/${encodeURIComponent(target._id)}`,
			{ email }
		);
		if (!result.ok) {
			openEmail(target, email);
			feedback.failed(result, emailForm);
			return;
		}
		feedback.done(`Email of ${target.email} changed to ${email}.`);
		await load();
	}

	async function onCreate(values: CreateAdminValues) {
		setCreating(true);
		try {
			const result = await request('POST', '/admin/api/admins', values);
			if (!result.ok) {
				feedback.failed(result, form);
				return;
			}
			feedback.done(`Administrator ${values.email} created.`);
			setOpen(false);
			form.resetFields();
			await load();
		} finally {
			setCreating(false);
		}
	}

	return (
		<>
			<PageHeader
				title="Administrators"
				actions={
					<Button
						type="primary"
						icon={<PlusOutlined />}
						onClick={() => setOpen(true)}
					>
						New administrator
					</Button>
				}
			/>
			{/*
			 * How administrators sign in — registration, email verification, an authenticator — is the
			 * console's own bucket's settings, edited where every bucket's are. Pointed at from here because
			 * this is where an operator looks for anything about administrators.
			 */}
			<Alert
				type="info"
				showIcon
				style={{ marginBottom: 16 }}
				title="Sign-in policy for administrators"
				description="Whether people may register an administrator account, whether administrators must verify their email, and whether an authenticator app is required are set on the Administrators bucket."
				action={
					onOpenSignInPolicy && (
						<Button
							size="small"
							onClick={onOpenSignInPolicy}
						>
							Open buckets
						</Button>
					)
				}
			/>
			{failed !== null ? (
				<LoadFailed
					reason={failed}
					onRetry={() => void load()}
				/>
			) : (
				<Table<AdminUser>
					rowKey="_id"
					loading={loading}
					dataSource={admins}
					columns={[
						{ title: 'Email', dataIndex: 'email' },
						{
							title: 'Status',
							key: 'status',
							render: (_: unknown, row: AdminUser) => (
								<Space
									size={4}
									wrap
								>
									{row.active ? (
										<Tag color="green">Active</Tag>
									) : (
										<Tag>Deactivated</Tag>
									)}
									{row.superAdmin && (
										<Tag color="gold">Super administrator</Tag>
									)}
									{!row.verified && <Tag color="orange">Unverified</Tag>}
								</Space>
							)
						},
						{
							title: '',
							key: 'actions',
							render: (_: unknown, row: AdminUser) => (
								<RowActions
									name={row.email}
									items={[
										{
											key: 'email',
											label: 'Change email…',
											group: 'edit',
											onClick: () => openEmail(row, row.email)
										},
										row.superAdmin
											? {
													key: 'withdraw',
													label: 'Withdraw super administration…',
													group: 'danger',
													onClick: () => void onSetSuperAdmin(row, false)
												}
											: {
													key: 'grant',
													label: 'Make super administrator…',
													group: 'state',
													onClick: () => void onSetSuperAdmin(row, true)
												}
									]}
								/>
							)
						}
					]}
				/>
			)}
			{/*
			 * Not destroyed when hidden: a refusal naming the field is set on it while it reopens, which a
			 * form still being mounted would drop.
			 */}
			<Modal
				title="Change email"
				open={editingEmail !== null}
				onCancel={() => setEditingEmail(null)}
				onOk={() => emailForm.submit()}
				okText="Change email"
				forceRender
			>
				<Form<{ email: string }>
					form={emailForm}
					layout="vertical"
					scrollToFirstError
					onFinish={({ email }) => {
						if (editingEmail) void onChangeEmail(editingEmail, email);
					}}
				>
					<Form.Item
						name="email"
						label="Email"
						rules={[{ required: true, type: 'email' }]}
						extra="The administrator must verify the new address before signing in, if administrators are required to verify theirs."
					>
						<Input autoComplete="off" />
					</Form.Item>
				</Form>
			</Modal>
			<Modal
				title="New administrator"
				open={open}
				onCancel={() => setOpen(false)}
				onOk={() => form.submit()}
				confirmLoading={creating}
				destroyOnHidden
			>
				<Form<CreateAdminValues>
					form={form}
					layout="vertical"
					scrollToFirstError
					onFinish={onCreate}
				>
					{/*
					 * An address beside a password is a sign-in form as far as a browser is concerned, and it
					 * filled this one with the *administrator's own* saved credentials — one distracted OK away
					 * from creating an account with their own email and password. `new-password` is the part
					 * that does the work: it is the documented signal not to offer a stored pair.
					 */}
					<Form.Item
						name="email"
						label="Email"
						rules={[{ required: true, type: 'email' }]}
					>
						<Input autoComplete="off" />
					</Form.Item>
					<Form.Item
						name="password"
						label="Password"
						rules={[{ required: true, min: 12 }]}
					>
						<Input.Password
							autoComplete="new-password"
							placeholder="at least 12 characters"
						/>
					</Form.Item>
				</Form>
			</Modal>
		</>
	);
}
