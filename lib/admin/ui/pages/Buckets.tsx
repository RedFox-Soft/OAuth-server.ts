import { useCallback, useEffect, useState } from 'react';
import {
	Table,
	Button,
	Modal,
	Form,
	Input,
	Radio,
	Space,
	Tag,
	Tooltip
} from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import type { UserBucket } from '../../../adapters/types.js';
import { Link, useNavigate } from '../frame/router.js';
import { bucketHref } from '../frame/routes.js';
import { bucketAddressFor } from '../bucketAddress.js';
import { ConfirmDestruction } from '../ConfirmDestruction.js';
import { MoveToGroup } from '../MoveToGroup.js';
import { isUndeletableBucket, reservedOf } from '../../consts.js';
import { PageHeader } from '../frame/PageHeader.js';
import { request } from '../frame/request.js';
import { useFeedback } from '../frame/feedback.js';
import { RowActions, type RowAction } from '../frame/RowActions.js';
import {
	bucketCan,
	type BucketBlockers,
	type BucketCan
} from '../frame/can.js';
import { meCan, useMe } from '../frame/me.js';
import { EmptyState, LoadFailed } from '../frame/states.js';

interface CreateBucketValues {
	name: string;
	/* Which form the operator chose. Never sent — the body carries `slug` or `host`, never both. */
	addressForm?: 'path' | 'host';
	slug?: string;
	host?: string;
}

/* A list row as the API presents it: the record, the caller's rights on it, and what blocks them. */
type BucketRow = UserBucket & {
	can?: Partial<BucketCan>;
	blockers?: BucketBlockers;
};

/*
 * Who may create, move and delete is what the server states (`me.can`, each row's `can`), never
 * reconstructed here from the caller's memberships.
 */
export function Buckets() {
	const [buckets, setBuckets] = useState<BucketRow[]>([]);
	const [loading, setLoading] = useState(true);
	const [loadError, setLoadError] = useState<string | null>(null);
	const [open, setOpen] = useState(false);
	const [creating, setCreating] = useState(false);
	const [form] = Form.useForm<CreateBucketValues>();
	const navigate = useNavigate();
	const feedback = useFeedback();
	const { me } = useMe();
	const mine = meCan(me);
	const [deleting, setDeleting] = useState<BucketRow | null>(null);
	const [heldUsers, setHeldUsers] = useState(0);
	const [destroying, setDestroying] = useState(false);
	const [moving, setMoving] = useState<BucketRow | null>(null);

	// Every state write follows an await, so the mount effect calls this without setting
	// `loading` first; `load` is the reload, which does.
	const fetchBuckets = useCallback(async () => {
		try {
			const result = await request<BucketRow[]>('GET', '/admin/api/buckets');
			if (result.ok) {
				setBuckets(result.data);
				setLoadError(null);
			} else {
				setLoadError(result.error.message);
			}
		} finally {
			setLoading(false);
		}
	}, []);
	function load() {
		setLoading(true);
		return fetchBuckets();
	}
	useEffect(() => {
		void fetchBuckets();
	}, [fetchBuckets]);

	async function onCreate(values: CreateBucketValues) {
		setCreating(true);
		try {
			/*
			 * One form or the other, never both. The API refuses a body carrying two addresses rather than
			 * preferring one, so sending the field the operator did not fill would turn their choice into a
			 * 400 they did not cause.
			 */
			const { addressForm, slug, host, ...rest } = values;
			const result = await request(
				'POST',
				'/admin/api/buckets',
				addressForm === 'host' ? { ...rest, host } : { ...rest, slug }
			);
			if (!result.ok) {
				feedback.failed(result, form);
				return;
			}
			feedback.done(`Bucket ${values.name} created.`);
			setOpen(false);
			form.resetFields();
			await load();
		} finally {
			setCreating(false);
		}
	}

	/*
	 * The account count is fetched when the dialog opens rather than listed in the table: it is a read
	 * per bucket, and a table of twenty buckets does not need twenty of them to answer a question
	 * nobody has asked yet. A failed read does not open the dialog: a count it never learned would read
	 * as "empty".
	 */
	async function openDelete(bucket: BucketRow) {
		const result = await request<unknown[]>(
			'GET',
			`/admin/api/buckets/${encodeURIComponent(bucket._id)}/users`
		);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		setHeldUsers(result.data.length);
		setDeleting(bucket);
	}

	async function onDelete(bucket: BucketRow, withCascade: boolean) {
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
			const result = await request<{ endUsersDestroyed?: number }>(
				'DELETE',
				`/admin/api/buckets/${encodeURIComponent(bucket._id)}${qs ? `?${qs}` : ''}`
			);
			if (!result.ok) {
				feedback.failed(result);
				return;
			}
			const destroyed = result.data.endUsersDestroyed ?? 0;
			feedback.done(
				destroyed > 0
					? `Bucket ${bucket.name} deleted with its ${String(destroyed)} end-user accounts.`
					: `Bucket ${bucket.name} deleted.`
			);
			setDeleting(null);
			await load();
		} finally {
			setDestroying(false);
		}
	}

	function rowActions(row: BucketRow): RowAction[] {
		const can = bucketCan(row);
		const items: RowAction[] = [];
		/*
		 * Nothing at all for the two buckets the server is built on, rather than a Delete that answers 403.
		 * A delete control beside the default bucket reads as an offer no matter what happens when it is
		 * pressed.
		 */
		if (isUndeletableBucket(row._id)) return items;
		if (can.move) {
			items.push({
				key: 'move',
				label: 'Move to group…',
				group: 'handover',
				onClick: () => setMoving(row)
			});
		}
		if (can.delete) {
			/*
			 * Named, not counted: "one project" leaves the administrator hunting through a list for which
			 * one. Refused here rather than inside the dialog, so nobody consents to destroying every
			 * account in a bucket only to be told no for a reason unrelated to the accounts.
			 */
			const usedBy = row.blockers?.usedByProjects ?? [];
			items.push({
				key: 'delete',
				label: 'Delete…',
				group: 'danger',
				onClick: () => void openDelete(row),
				blocked:
					usedBy.length > 0
						? `Used by ${usedBy.map((p) => p.name).join(', ')} — assign them another bucket first`
						: null
			});
		}
		return items;
	}

	const createButton = mine.createBucket ? (
		<Button
			type="primary"
			icon={<PlusOutlined />}
			onClick={() => setOpen(true)}
		>
			New bucket
		</Button>
	) : null;

	return (
		<>
			<PageHeader
				title="Buckets"
				actions={createButton}
			/>
			{loadError !== null ? (
				<LoadFailed
					reason={loadError}
					onRetry={() => void load()}
				/>
			) : (
				<Table<BucketRow>
					rowKey="_id"
					loading={loading}
					dataSource={buckets}
					locale={{
						emptyText: (
							<EmptyState
								purpose="No user buckets in this scope yet. A bucket holds the end-user accounts a project authenticates."
								create={createButton}
							/>
						)
					}}
					columns={[
						{
							title: 'Name',
							dataIndex: 'name',
							render: (name: string, row: BucketRow) => {
								const reserved = reservedOf(row._id);
								return (
									<Space>
										<Link href={bucketHref(row._id)}>{name}</Link>
										{reserved === 'administrators' && (
											<Tooltip title="The console's own bucket: its accounts are this instance's administrators.">
												<Tag color="gold">Administrators</Tag>
											</Tooltip>
										)}
										{reserved === 'default' && <Tag>Default</Tag>}
									</Space>
								);
							}
						},
						{
							title: 'Address',
							dataIndex: 'slug',
							/*
							 * The address an operator can integrate a client against, which is not the same
							 * question as whether the bucket has a slug — see `bucketAddressFor`.
							 */
							render: (_slug: string | undefined, row: BucketRow) => {
								const address = bucketAddressFor(row);
								if (address.kind === 'prefix')
									return <code>{address.path}</code>;
								if (address.kind === 'host') {
									return (
										<Tooltip title="Served at a host of its own. Its tokens carry that origin as their issuer, and its sign-in cookie is isolated by the browser rather than by name.">
											<code>{`https://${address.host}`}</code>
										</Tooltip>
									);
								}
								if (address.kind === 'none') return <Tag>not addressable</Tag>;
								return (
									<Tooltip title="Served at the server's own address, with no prefix, and its tokens carry the server's own issuer.">
										<Tag color="blue">served at the root</Tag>
									</Tooltip>
								);
							}
						},
						{
							title: 'Projects',
							render: (_: unknown, row: BucketRow) =>
								row.blockers?.usedByProjects.length ?? 0
						},
						{
							title: '',
							render: (_: unknown, row: BucketRow) => (
								<RowActions
									name={row.name}
									items={rowActions(row)}
								/>
							)
						}
					]}
				/>
			)}
			{moving && (
				<MoveToGroup
					kind="bucket"
					id={moving._id}
					name={moving.name}
					sourceGroupId={moving.ownerGroupId}
					onClose={() => setMoving(null)}
					onMoved={() => {
						setMoving(null);
						void load();
					}}
				/>
			)}
			{deleting && (
				<ConfirmDestruction
					open
					title={`Delete ${deleting.name}?`}
					okText="Delete bucket"
					consequences={[
						'The bucket is gone permanently. There is nothing left to inspect or restore.',
						`Its sign-in address stops answering, and every token it minted stops being issued from it.`
					]}
					cascade={
						heldUsers > 0
							? {
									noun: 'end-user accounts',
									count: heldUsers,
									onInspect: () => {
										setDeleting(null);
										void navigate(bucketHref(deleting._id));
									},
									inspectLabel: 'Look at the accounts first'
								}
							: undefined
					}
					busy={destroying}
					onCancel={() => setDeleting(null)}
					onConfirm={(withCascade) => void onDelete(deleting, withCascade)}
				/>
			)}
			<Modal
				title="New bucket"
				open={open}
				onCancel={() => setOpen(false)}
				onOk={() => form.submit()}
				okText="Create bucket"
				confirmLoading={creating}
				destroyOnHidden
			>
				<Form<CreateBucketValues>
					form={form}
					layout="vertical"
					onFinish={onCreate}
					scrollToFirstError
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
					{/*
					 * Which form, asked before the value, because the two are alternatives rather than a
					 * field and an option. The API refuses a body carrying both, so a form offering both at
					 * once would invite a refusal the operator could not have anticipated.
					 *
					 * The help text states the trade-off rather than recommending blindly: a host is better
					 * where a deployment can pay for one, and the payment is a DNS record and a certificate
					 * this server neither creates nor can see.
					 *
					 * Asked only of someone who may give away a name in the deployment's domain; anyone else
					 * has one form, and a choice of one is not a question.
					 */}
					{mine.createHost && (
						<Form.Item
							name="addressForm"
							label="Address form"
							initialValue="path"
							tooltip="A host isolates this bucket's sign-in cookie by origin and publishes one metadata location instead of two. It needs a DNS record and a TLS certificate, which you provide — this server creates neither."
						>
							<Radio.Group
								optionType="button"
								options={[
									{ label: 'Path', value: 'path' },
									{ label: 'Host of its own', value: 'host' }
								]}
							/>
						</Form.Item>
					)}
					<Form.Item<CreateBucketValues>
						noStyle
						shouldUpdate={(before, after) =>
							before.addressForm !== after.addressForm
						}
					>
						{({ getFieldValue }) =>
							getFieldValue('addressForm') === 'host' ? (
								<Form.Item
									name="host"
									label="Hostname"
									tooltip="Where this bucket is served, and the issuer in the tokens it mints. Changing it later breaks every client integrated with this bucket."
									rules={[
										{ required: true },
										{
											pattern: /^[a-z0-9-]+(\.[a-z0-9-]+)+$/i,
											message:
												'a fully qualified hostname — no scheme, no path, no port, no wildcard'
										},
										{ max: 253 }
									]}
									extra="Point this name at the deployment and obtain a certificate for it. Until a request arrives, the bucket page will say so."
								>
									<Input placeholder="acme.auth.example.com" />
								</Form.Item>
							) : (
								<Form.Item
									label="Address"
									required
									tooltip="Where this bucket is served, and the issuer in the tokens it mints. Changing it later breaks every client integrated with this bucket."
								>
									{/* The inner item binds the field; the outer one labels it and shows its errors. */}
									<Space.Compact block>
										<Space.Addon>/</Space.Addon>
										<Form.Item
											name="slug"
											noStyle
											messageVariables={{ label: 'Address' }}
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
											<Input placeholder="acme" />
										</Form.Item>
									</Space.Compact>
								</Form.Item>
							)
						}
					</Form.Item>
				</Form>
			</Modal>
		</>
	);
}
