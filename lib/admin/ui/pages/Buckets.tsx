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
	Tooltip,
	Typography
} from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import type { UserBucket } from '../../../adapters/types.js';
import { Link, useNavigate } from '../frame/router.js';
import { bucketHref, connectionHref } from '../frame/routes.js';
import { bucketAddressFor, originOf } from '../bucketAddress.js';
import { MoveToGroup } from '../MoveToGroup.js';
import { isUndeletableBucket, reservedOf } from '../../consts.js';
import { GroupField } from '../frame/CreateDestination.js';
import { PageHeader } from '../frame/PageHeader.js';
import { request } from '../frame/request.js';
import { useFeedback } from '../frame/feedback.js';
import { RowActions, type RowAction } from '../frame/RowActions.js';
import {
	bucketCan,
	type BucketBlockers,
	type BucketCan
} from '../frame/can.js';
import { useInstanceHost } from '../frame/instance.js';
import { meCan, useMe, type AddressFormChoice } from '../frame/me.js';
import { EmptyState, LoadFailed } from '../frame/states.js';
import { DeleteBucketDialog } from './DeleteBucketDialog.js';
import { useScheduledActions } from './ScheduledBanner.js';
import { ADDRESS_FORM_CHOICE, type BucketDeletionView } from './bucketView.js';

interface CreateBucketValues {
	name: string;
	/* What the bucket's people see on the page where they allow an app access; empty means its address. */
	displayName?: string;
	/*
	 * Which form the operator chose. Sent only for a subdomain: the body carries `slug` or `host`, never
	 * both, and a slug without a form is a path.
	 */
	addressForm?: AddressFormChoice;
	slug?: string;
	host?: string;
	/* Who can create accounts (specs/083): closed unless the creator opens it. */
	registrationOpen?: boolean;
	/* Chosen in the dialog (specs/087); the header's current team by default. */
	teamId?: string;
}

/* A list row as the API presents it: the record, the caller's rights on it, and what blocks them. */
type BucketRow = Omit<UserBucket, 'deletion' | 'ownerGroupId'> & {
	/* The owning team, under its edge name (specs/100). */
	ownerTeamId: string;
	can?: Partial<BucketCan>;
	/* specs/090: present while the bucket is scheduled for deletion. */
	deletion?: BucketDeletionView;
	blockers?: BucketBlockers;
	/* specs/081: whether a host has been reached, whether a connection holds, the issuer to copy. */
	hostReached?: boolean;
	held?: boolean;
	/* specs/088: the held connection, so the mark opens the page that can end the hold. */
	heldConnectionId?: string;
	issuer?: string | null;
};

/* The two buckets the server is built on, listed last so the buckets an operator works with come first. */
function pinnedLast(rows: BucketRow[]): BucketRow[] {
	return [
		...rows.filter((r) => !reservedOf(r._id)),
		...rows.filter((r) => reservedOf(r._id))
	];
}

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
	const feedback = useFeedback();
	const scheduled = useScheduledActions({
		onRestored: () => void load(),
		onDeleted: () => void load()
	});
	const navigate = useNavigate();
	const { me, reload } = useMe();
	const mine = meCan(me);
	const projectsFull =
		mine.projects && mine.projects.count >= mine.projects.max
			? mine.projects
			: null;
	const instanceHost = useInstanceHost();
	const slugTyped = Form.useWatch('slug', form);
	const [deleting, setDeleting] = useState<BucketRow | null>(null);
	const [moving, setMoving] = useState<BucketRow | null>(null);
	// Owning groups by name, for a super administrator's Owner column.
	const [groupNames, setGroupNames] = useState<Map<string, string>>(new Map());
	const superAdmin = me?.superAdmin === true;

	// Every state write follows an await, so the mount effect calls this without setting
	// `loading` first; `load` is the reload, which does.
	const fetchBuckets = useCallback(async () => {
		try {
			const result = await request<BucketRow[]>('GET', '/admin/api/projects');
			if (result.ok) {
				setBuckets(pinnedLast(result.data));
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
	useEffect(() => {
		if (!superAdmin) return;
		void request<{ _id: string; name: string }[]>(
			'GET',
			'/admin/api/teams'
		).then((result) => {
			if (result.ok) {
				setGroupNames(new Map(result.data.map((g) => [g._id, g.name])));
			}
		});
	}, [superAdmin]);

	async function onCreate(values: CreateBucketValues) {
		setCreating(true);
		try {
			/*
			 * One form or the other, never both. The API refuses a body carrying two addresses rather than
			 * preferring one, so sending the field the operator did not fill would turn their choice into a
			 * 400 they did not cause.
			 */
			const { addressForm, slug, host, displayName, ...rest } = values;
			const shown = displayName?.trim();
			const named = shown ? { ...rest, displayName: shown } : rest;
			// The choice is not rendered when only one form is offered, and then that one is the form.
			const chosen = addressForm ?? mine.addressForms[0];
			/*
			 * A plan without a custom address name (specs/102) is given no slug at all: the server generates one in
			 * the chosen form, and refuses a named one.
			 */
			const slugPart = mine.nameSlug === false ? {} : { slug };
			const result = await request<{ _id: string }>(
				'POST',
				'/admin/api/projects',
				chosen === 'host'
					? { ...named, host }
					: chosen === 'subdomain'
						? { ...named, ...slugPart, addressForm: 'subdomain' }
						: { ...named, ...slugPart }
			);
			if (!result.ok) {
				feedback.failed(result, form);
				return;
			}
			feedback.done(`Project ${values.name} created.`);
			setOpen(false);
			form.resetFields();
			// The plan's count of the operator's projects moved; `me.can.projects` says so.
			void reload();
			// Opened at once: it may belong to a team other than the header's, where the list would not show it.
			void navigate(bucketHref(result.data._id));
		} finally {
			setCreating(false);
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
				label: 'Move to team…',
				group: 'handover',
				onClick: () => setMoving(row)
			});
		}
		if (can.delete && row.deletion) {
			items.push(
				{
					key: 'restore',
					label: 'Restore',
					group: 'handover',
					onClick: () => void scheduled.restore(row)
				},
				{
					key: 'purge',
					label: 'Delete now…',
					group: 'danger',
					onClick: () => scheduled.deleteNow(row)
				}
			);
			return items;
		}
		if (can.delete) {
			/*
			 * A bucket that still holds applications or APIs is refused by the server, which names them; the
			 * list does not read every bucket's contents to say so in advance — its Settings tab does.
			 */
			items.push({
				key: 'delete',
				label: 'Delete…',
				group: 'danger',
				onClick: () => setDeleting(row)
			});
		}
		return items;
	}

	const createButton = mine.createProject ? (
		<Tooltip
			title={
				projectsFull
					? `You own ${String(projectsFull.count)} of ${String(projectsFull.max)} projects on the ${projectsFull.plan.name} plan. Ask for a larger plan to create more.`
					: undefined
			}
		>
			<Button
				type="primary"
				icon={<PlusOutlined />}
				disabled={projectsFull !== null}
				onClick={() => setOpen(true)}
			>
				New project
			</Button>
		</Tooltip>
	) : null;

	return (
		<>
			<PageHeader
				title="Projects"
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
						// Before the first answer nothing is known, and "none yet" would be a claim.
						emptyText: loading ? (
							' '
						) : (
							<EmptyState
								purpose="A project holds the people who sign in to your apps, and the apps and APIs that sign them in. Create one, then register your first application in it."
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
										{/* The console's own bucket lives on the Administrators page (specs/083). */}
										<Link
											href={
												reserved === 'administrators'
													? '/admin/administrators'
													: bucketHref(row._id)
											}
										>
											{name}
										</Link>
										{row.deletion && (
											<Tag color="warning">
												Deletes on{' '}
												{new Date(row.deletion.purgeAt).toLocaleDateString()}
											</Tag>
										)}
										{row.held && (
											<Tooltip title="A provisioning connection is holding a mass deprovisioning: the people it tried to remove keep their access until someone releases it.">
												{row.heldConnectionId ? (
													<Link
														href={connectionHref(row._id, row.heldConnectionId)}
													>
														<Tag color="red">On hold</Tag>
													</Link>
												) : (
													<Tag color="red">On hold</Tag>
												)}
											</Tooltip>
										)}
										{reserved === 'administrators' && (
											<Tooltip title="The console's own project: its accounts are this instance's administrators.">
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
								const address = bucketAddressFor(row, instanceHost);
								if (address.kind === 'prefix')
									return <code>{address.path}</code>;
								if (address.kind === 'host' || address.kind === 'subdomain') {
									return (
										<Space
											orientation="vertical"
											size={0}
										>
											<Tooltip
												title={`Served at ${address.kind === 'host' ? 'a host of its own' : 'a subdomain of this instance'}. Its tokens carry that origin as their issuer, and its sign-in cookie is isolated by the browser rather than by name.`}
											>
												<code>{originOf(address.host)}</code>
											</Tooltip>
											{row.hostReached === false && (
												<Typography.Text type="warning">
													Not reached yet
												</Typography.Text>
											)}
										</Space>
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
							title: 'Issuer',
							key: 'issuer',
							render: (_: unknown, row: BucketRow) =>
								row.issuer ? (
									<Typography.Text
										copyable={{ text: row.issuer }}
										type="secondary"
									>
										Copy
									</Typography.Text>
								) : null
						},
						...(superAdmin
							? [
									{
										title: 'Owner',
										key: 'owner',
										render: (_: unknown, row: BucketRow) =>
											reservedOf(row._id)
												? '—'
												: (groupNames.get(row.ownerTeamId) ?? row.ownerTeamId)
									}
								]
							: []),
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
					id={moving._id}
					name={moving.name}
					sourceGroupId={moving.ownerTeamId}
					onClose={() => setMoving(null)}
					onMoved={() => {
						setMoving(null);
						void load();
					}}
				/>
			)}
			{deleting && (
				<DeleteBucketDialog
					bucket={deleting}
					onClose={() => setDeleting(null)}
					onDeleted={({ purgeAt }) => {
						feedback.done(
							purgeAt
								? `${deleting.name} scheduled for deletion on ${new Date(purgeAt).toLocaleDateString()}.`
								: `${deleting.name} scheduled for deletion.`
						);
						setDeleting(null);
						void load();
					}}
				/>
			)}
			{scheduled.dialog}
			<Modal
				title="New project"
				open={open}
				onCancel={() => setOpen(false)}
				onOk={() => form.submit()}
				okText="Create project"
				confirmLoading={creating}
				destroyOnHidden
			>
				<Form<CreateBucketValues>
					form={form}
					layout="vertical"
					onFinish={onCreate}
					scrollToFirstError
				>
					<GroupField />
					<Form.Item
						name="name"
						label="Name"
						rules={[{ required: true }]}
					>
						<Input />
					</Form.Item>
					<Form.Item
						name="displayName"
						label="Name shown to users"
						extra="What people see at the top of the page where they allow an app access — for example “Acme ID”. Leave it empty to show the project’s address instead. The name above is only for this console."
					>
						<Input
							maxLength={60}
							placeholder="the project’s address"
						/>
					</Form.Item>
					{/*
					 * The address, and not a second name: everything beneath it — this bucket's endpoints,
					 * its metadata, the issuer in every token it mints — is built from this value, and it
					 * cannot be changed afterwards. Said here rather than left to a validation error,
					 * because an operator choosing one has no other way to know it is permanent.
					 */}
					{/*
					 * Which form, asked before the value, because the forms are alternatives rather than a
					 * field and an option. The API refuses a body carrying both a slug and a host, so a form
					 * offering both at once would invite a refusal the operator could not have anticipated.
					 *
					 * Exactly the forms the server says this operator may give, in its order, the first
					 * selected (`me.can.addressForms`, specs/101). A choice of one is not a question, so it is
					 * not asked.
					 *
					 * The help text states the trade-off rather than recommending blindly: an origin of its own
					 * isolates the project's cookies, and costs DNS and a certificate this server neither
					 * creates nor can see — once for every subdomain, or once per hostname.
					 */}
					{mine.addressForms.length > 1 && (
						<Form.Item
							name="addressForm"
							label="Address form"
							initialValue={mine.addressForms[0]}
							tooltip="A subdomain or a hostname gives this project an origin of its own, which isolates its sign-in cookie and publishes one metadata location instead of two. A subdomain is covered by this instance's wildcard DNS record and certificate; a hostname of its own needs a DNS record and a TLS certificate you provide — this server creates neither."
						>
							<Radio.Group
								optionType="button"
								options={mine.addressForms.map((value) => ({
									label: ADDRESS_FORM_CHOICE[value],
									value
								}))}
							/>
						</Form.Item>
					)}
					<Form.Item<CreateBucketValues>
						noStyle
						shouldUpdate={(before, after) =>
							before.addressForm !== after.addressForm
						}
					>
						{({ getFieldValue }) => {
							const chosen =
								(getFieldValue('addressForm') as
									AddressFormChoice | undefined) ?? mine.addressForms[0];
							if (chosen === 'host') {
								return (
									<Form.Item
										name="host"
										label="Hostname"
										tooltip="Where this project is served, and the issuer in the tokens it mints. Changing it later breaks every client integrated with this project."
										rules={[
											{ required: true },
											{
												pattern: /^[a-z0-9-]+(\.[a-z0-9-]+)+$/i,
												message:
													'a fully qualified hostname — no scheme, no path, no port, no wildcard'
											},
											{ max: 253 }
										]}
										extra="Point this name at the deployment and obtain a certificate for it. Until a request arrives, the project page will say so."
									>
										<Input placeholder="acme.auth.example.com" />
									</Form.Item>
								);
							}
							const subdomain = chosen === 'subdomain';
							if (mine.nameSlug === false) {
								return (
									<Form.Item
										label="Address"
										tooltip="Where this project is served, and the issuer in the tokens it mints."
									>
										<Typography.Text type="secondary">
											{subdomain
												? `A name of eight letters and digits is generated for it, served as a subdomain of ${instanceHost}.`
												: 'A name of eight letters and digits is generated for it, served as a path of this server.'}{' '}
											Choosing the name yourself needs a larger plan.
										</Typography.Text>
									</Form.Item>
								);
							}
							const label =
								typeof slugTyped === 'string' && slugTyped.trim()
									? slugTyped.trim()
									: 'acme';
							return (
								<Form.Item
									label="Address"
									required
									tooltip="Where this project is served, and the issuer in the tokens it mints. Changing it later breaks every client integrated with this project."
									extra={
										subdomain ? (
											<>
												Served at{' '}
												<Typography.Text code>
													{originOf(`${label}.${instanceHost}`)}
												</Typography.Text>
											</>
										) : undefined
									}
								>
									{/* The inner item binds the field; the outer one labels it and shows its errors. */}
									<Space.Compact block>
										{!subdomain && <Space.Addon>/</Space.Addon>}
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
										{subdomain && <Space.Addon>.{instanceHost}</Space.Addon>}
									</Space.Compact>
								</Form.Item>
							);
						}}
					</Form.Item>
					<Form.Item<CreateBucketValues>
						name="registrationOpen"
						label="Who can create accounts?"
						initialValue={false}
						extra="You can change this later on the project's Sign-in tab."
					>
						<Radio.Group
							options={[
								{
									label:
										'Only administrators, identity providers and directories',
									value: false
								},
								{
									label: 'Anyone who can reach the sign-in page',
									value: true
								}
							]}
						/>
					</Form.Item>
				</Form>
			</Modal>
		</>
	);
}
