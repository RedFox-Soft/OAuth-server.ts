import { useEffect, useState } from 'react';
import {
	Table,
	Button,
	Modal,
	Form,
	Input,
	Select,
	Space,
	Tag,
	Tooltip,
	message
} from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import type { UserBucket, Project } from '../../../adapters/types.js';
import { BucketDetail } from './BucketDetail.js';
import { bucketAddressFor } from '../bucketAddress.js';
import { ConfirmDestruction } from '../ConfirmDestruction.js';
import { isUndeletableBucket } from '../../consts.js';

interface CreateBucketValues {
	name: string;
	slug: string;
	roles?: string[];
}

export function Buckets({ isSuperAdmin }: { isSuperAdmin: boolean }) {
	const [buckets, setBuckets] = useState<UserBucket[]>([]);
	const [projects, setProjects] = useState<Project[]>([]);
	const [loading, setLoading] = useState(true);
	const [open, setOpen] = useState(false);
	const [creating, setCreating] = useState(false);
	const [form] = Form.useForm<CreateBucketValues>();
	const [openBucketId, setOpenBucketId] = useState<string | null>(null);
	const [deleting, setDeleting] = useState<UserBucket | null>(null);
	const [heldUsers, setHeldUsers] = useState(0);
	const [destroying, setDestroying] = useState(false);

	async function load() {
		setLoading(true);
		try {
			const [b, p] = await Promise.all([
				fetch('/admin/api/buckets'),
				fetch('/admin/api/projects')
			]);
			if (b.ok) setBuckets((await b.json()) as UserBucket[]);
			if (p.ok) setProjects((await p.json()) as Project[]);
		} finally {
			setLoading(false);
		}
	}
	useEffect(() => {
		load();
	}, []);

	async function onCreate(values: CreateBucketValues) {
		setCreating(true);
		try {
			const res = await fetch('/admin/api/buckets', {
				method: 'POST',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify(values)
			});
			if (!res.ok) {
				const body = (await res.json().catch(() => null)) as {
					message?: string;
				} | null;
				message.error(body?.message || 'failed to create bucket');
				return;
			}
			setOpen(false);
			form.resetFields();
			await load();
		} finally {
			setCreating(false);
		}
	}

	function assignedProjects(bucketId: string): Project[] {
		return projects.filter((p) => p.bucketId === bucketId);
	}

	function projectCount(bucketId: string): number {
		return assignedProjects(bucketId).length;
	}

	/*
	 * The account count is fetched when the dialog opens rather than listed in the table: it is a read
	 * per bucket, and a table of twenty buckets does not need twenty of them to answer a question
	 * nobody has asked yet.
	 */
	async function openDelete(bucket: UserBucket) {
		const res = await fetch(
			`/admin/api/buckets/${encodeURIComponent(bucket._id)}/users`
		);
		const users = res.ok ? ((await res.json()) as unknown[]) : [];
		setHeldUsers(users.length);
		setDeleting(bucket);
	}

	async function onDelete(bucket: UserBucket, withCascade: boolean) {
		setDestroying(true);
		try {
			const params = new URLSearchParams();
			if (withCascade) {
				params.set('cascade', 'endusers');
				// The number the administrator just reviewed. An account that arrived while they were
				// reading makes this stale, and the server refuses rather than destroying it.
				params.set('expect', String(heldUsers));
			}
			const qs = params.toString();
			const res = await fetch(
				`/admin/api/buckets/${encodeURIComponent(bucket._id)}${qs ? `?${qs}` : ''}`,
				{ method: 'DELETE' }
			);
			if (!res.ok) {
				const body = (await res.json().catch(() => null)) as {
					message?: string;
				} | null;
				message.error(body?.message || `request failed (${res.status})`);
				return;
			}
			const body = (await res.json()) as { endUsersDestroyed?: number };
			message.success(
				`Bucket deleted — ${body.endUsersDestroyed ?? 0} end-user accounts destroyed`
			);
			setDeleting(null);
			await load();
		} finally {
			setDestroying(false);
		}
	}

	if (openBucketId) {
		return (
			<BucketDetail
				bucketId={openBucketId}
				onBack={() => {
					setOpenBucketId(null);
					load();
				}}
				isSuperAdmin={isSuperAdmin}
			/>
		);
	}

	return (
		<>
			{isSuperAdmin && (
				<div style={{ marginBottom: 16, textAlign: 'right' }}>
					<Button
						type="primary"
						icon={<PlusOutlined />}
						onClick={() => setOpen(true)}
					>
						New bucket
					</Button>
				</div>
			)}
			<Table<UserBucket>
				rowKey="_id"
				loading={loading}
				dataSource={buckets}
				locale={{
					emptyText:
						'No user buckets in this scope yet. A bucket holds the end-user accounts a project authenticates.'
				}}
				columns={[
					{ title: 'Name', dataIndex: 'name' },
					{
						title: 'Address',
						dataIndex: 'slug',
						/*
						 * The address an operator can integrate a client against, which is not the same
						 * question as whether the bucket has a slug — see `bucketAddressFor`.
						 */
						render: (_slug: string | undefined, row: UserBucket) => {
							const address = bucketAddressFor(row);
							if (address.kind === 'prefix') return <code>{address.path}</code>;
							if (address.kind === 'none') return <Tag>not addressable</Tag>;
							return (
								<Tooltip title="Served at the server's own address, with no prefix, and its tokens carry the server's own issuer.">
									<Tag color="blue">served at the root</Tag>
								</Tooltip>
							);
						}
					},
					{
						title: 'Roles',
						dataIndex: 'roles',
						render: (roles: string[]) =>
							roles.map((r) => <Tag key={r}>{r}</Tag>)
					},
					{
						title: 'Projects',
						render: (_: unknown, row: UserBucket) => projectCount(row._id)
					},
					{
						title: '',
						render: (_: unknown, row: UserBucket) => (
							<Space>
								<Button
									size="small"
									onClick={() => setOpenBucketId(row._id)}
								>
									Users
								</Button>
								{/*
								 * No action at all for the two buckets the server is built on, rather
								 * than one that answers 403. An administrator should not be invited into
								 * a refusal — and a delete button beside the default bucket reads as an
								 * offer no matter what happens when it is pressed.
								 */}
								{isUndeletableBucket(row._id) ? (
									<Tooltip title="Part of the server itself — the instance needs somewhere to sign people in.">
										<Button
											size="small"
											disabled
										>
											Delete
										</Button>
									</Tooltip>
								) : (
									<Button
										size="small"
										danger
										onClick={() => openDelete(row)}
									>
										Delete
									</Button>
								)}
							</Space>
						)
					}
				]}
			/>
			{deleting && (
				<ConfirmDestruction
					open
					title={`Delete ${deleting.name}?`}
					consequences={[
						'The bucket is gone permanently. There is nothing left to inspect or restore.',
						`Its sign-in address stops answering, and every token it minted stops being issued from it.`,
						/*
						 * The blocker no election clears, said before the administrator elects anything.
						 * Otherwise they consent to destroying every account in it and are then refused
						 * for a reason that has nothing to do with the accounts.
						 */
						...(assignedProjects(deleting._id).length > 0
							? [
									/*
									 * Named, not counted. The screen already holds the projects, and "one
									 * project" leaves the administrator hunting through a list for which
									 * one — the search this is here to save them.
									 */
									`Still assigned to ${assignedProjects(deleting._id)
										.map((p) => p.name)
										.join(
											', '
										)} — clear the assignment there first; no election deletes it while it is assigned.`
								]
							: [])
					]}
					cascade={
						heldUsers > 0
							? {
									noun: 'end-user accounts',
									count: heldUsers,
									onInspect: () => setOpenBucketId(deleting._id),
									inspectLabel: 'Look at the accounts first'
								}
							: undefined
					}
					busy={destroying}
					onCancel={() => setDeleting(null)}
					onConfirm={(withCascade) => onDelete(deleting, withCascade)}
				/>
			)}
			<Modal
				title="New bucket"
				open={open}
				onCancel={() => setOpen(false)}
				onOk={() => form.submit()}
				confirmLoading={creating}
				destroyOnHidden
			>
				<Form<CreateBucketValues>
					form={form}
					layout="vertical"
					onFinish={onCreate}
				>
					<Form.Item
						name="name"
						label="Name"
						rules={[{ required: true }]}
					>
						<Input />
					</Form.Item>
					{/*
					 * The address, and not a second name: everything beneath it — this bucket's endpoints,
					 * its metadata, the issuer in every token it mints — is built from this value, and it
					 * cannot be changed afterwards. Said here rather than left to a validation error,
					 * because an operator choosing one has no other way to know it is permanent.
					 */}
					<Form.Item
						name="slug"
						label="Address"
						tooltip="Where this bucket is served, and the issuer in the tokens it mints. Cannot be changed later."
						rules={[
							{ required: true },
							{
								pattern: /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/,
								message:
									'lowercase letters, digits and hyphens; not starting or ending with a hyphen'
							},
							{ max: 63 }
						]}
					>
						<Input
							placeholder="acme"
							addonBefore="/"
						/>
					</Form.Item>
					<Form.Item
						name="roles"
						label="Roles"
					>
						<Select
							mode="tags"
							placeholder="add role names"
						/>
					</Form.Item>
				</Form>
			</Modal>
		</>
	);
}
