import { useCallback, useEffect, useState } from 'react';
import {
	Alert,
	Button,
	Card,
	Flex,
	Input,
	Select,
	Skeleton,
	Table,
	Tag,
	Typography
} from 'antd';
import { PageHeader } from '../../frame/PageHeader.js';
import { LoadFailed, NoAccess } from '../../frame/states.js';
import { bucketHref, connectionHref, userHref } from '../../frame/routes.js';
import { Link, useNavigate } from '../../frame/router.js';
import { request } from '../../frame/request.js';
import { useFeedback } from '../../frame/feedback.js';
import { useConfirm } from '../../frame/confirm.js';
import { bucketCan } from '../../frame/can.js';
import {
	PreviewConfirm,
	type PreviewStep
} from '../../frame/PreviewConfirm.js';
import type { BucketView } from '../bucketView.js';
import type { ConnectionView } from '../ProvisioningPanel.js';
import { UserSearchSelect } from '../users/UserSearchSelect.js';
import {
	RenameGroupModal,
	groupsApi,
	useDeleteGroup,
	type GroupView
} from './groupShared.js';

interface MemberView {
	id: string;
	email: string | null;
	userName?: string;
}

/* The server's account of a hand-over (specs/084 R5): who the directory already manages, who it does not. */
interface HandOverPreview {
	consequences: string[];
	expect: { connectionId: string; managed: number; foreign: number };
	blockers: { id: string; email: string | null }[];
	message?: string;
}

const PAGE = 100;
const MAX_ADD = 1000;

function isHandOverPreview(value: unknown): value is HandOverPreview {
	return (
		typeof value === 'object' &&
		value !== null &&
		typeof (value as { expect?: unknown }).expect === 'object'
	);
}

/*
 * One group of end users, at an address of its own (specs/084 US7): its members, paged from the server, and
 * the acts that change what it grants. A group a directory keeps is shown as such, once, with no controls the
 * server would refuse.
 */
export function UserGroupPage({
	bucketId,
	groupId
}: {
	bucketId: string;
	groupId: string;
}) {
	const feedback = useFeedback();
	const confirm = useConfirm();
	const navigate = useNavigate();
	const deleteGroup = useDeleteGroup(bucketId);
	const [bucket, setBucket] = useState<BucketView | null>(null);
	const [group, setGroup] = useState<GroupView | null>(null);
	const [connections, setConnections] = useState<ConnectionView[]>([]);
	const [loadStatus, setLoadStatus] = useState<number | null>(null);
	const [loadMessage, setLoadMessage] = useState<string | null>(null);
	const [loading, setLoading] = useState(true);
	const [members, setMembers] = useState<MemberView[]>([]);
	const [memberTotal, setMemberTotal] = useState(0);
	const [memberPage, setMemberPage] = useState(1);
	const [membersLoading, setMembersLoading] = useState(true);
	const [adding, setAdding] = useState<string[]>([]);
	const [addBusy, setAddBusy] = useState(false);
	const [renaming, setRenaming] = useState(false);
	const [handOver, setHandOver] = useState(false);
	const [target, setTarget] = useState<string | undefined>(undefined);
	const [preview, setPreview] = useState<HandOverPreview | null>(null);
	const [typed, setTyped] = useState('');

	const api = groupsApi(bucketId, groupId);

	// Every state write follows an await, so the mount effect calls this without setting `loading` first.
	const fetchGroup = useCallback(async () => {
		try {
			const [b, g, c] = await Promise.all([
				request<BucketView>(
					'GET',
					`/admin/api/buckets/${encodeURIComponent(bucketId)}`
				),
				request<GroupView>('GET', api),
				request<ConnectionView[]>(
					'GET',
					`/admin/api/buckets/${encodeURIComponent(bucketId)}/provisioning-connections`
				)
			]);
			if (!b.ok) {
				setLoadStatus(b.status);
				setLoadMessage(b.error.message);
				return;
			}
			setBucket(b.data);
			if (!g.ok) {
				setLoadStatus(g.status);
				setLoadMessage(g.error.message);
				return;
			}
			setLoadStatus(null);
			setGroup(g.data);
			if (c.ok) setConnections(c.data);
		} finally {
			setLoading(false);
		}
	}, [bucketId, api]);

	const fetchMembers = useCallback(
		async (page: number) => {
			try {
				const result = await request<{
					totalResults: number;
					members: MemberView[];
				}>(
					'GET',
					`${api}/members?startIndex=${(page - 1) * PAGE + 1}&count=${PAGE}`
				);
				if (!result.ok) {
					feedback.failed(result);
					return;
				}
				setMembers(result.data.members);
				setMemberTotal(result.data.totalResults);
				setMemberPage(page);
			} finally {
				setMembersLoading(false);
			}
		},
		[api, feedback]
	);

	useEffect(() => {
		void fetchGroup();
		void fetchMembers(1);
	}, [fetchGroup, fetchMembers]);

	const can = bucketCan(bucket);
	const listHref = bucketHref(bucketId, 'user-groups');

	if (loadStatus !== null) {
		return loadStatus === 403 || loadStatus === 404 ? (
			<NoAccess
				what="user group"
				backHref={bucket ? listHref : '/admin/buckets'}
				backLabel={bucket ? 'Back to User groups' : 'Back to Buckets'}
			/>
		) : (
			<LoadFailed
				reason={loadMessage ?? undefined}
				onRetry={() => void fetchGroup()}
			/>
		);
	}

	const keeper = group?.provisionedBy
		? (connections.find((c) => c.id === group.provisionedBy) ?? null)
		: null;
	const keptByDirectory = group?.provisionedBy !== undefined;
	const membersEditable = group !== null && !keptByDirectory && can.manageUsers;

	async function reloadAll(page = memberPage) {
		setMembersLoading(true);
		await Promise.all([fetchGroup(), fetchMembers(page)]);
	}

	async function addMembers() {
		if (!group || adding.length === 0) return;
		setAddBusy(true);
		try {
			const result = await request('POST', `${api}/members`, {
				userIds: adding
			});
			if (!result.ok) {
				feedback.failed(result);
				return;
			}
			feedback.done(
				adding.length === 1
					? `1 person added to ${group.displayName}.`
					: `${String(adding.length)} people added to ${group.displayName}.`
			);
			setAdding([]);
			await reloadAll();
		} finally {
			setAddBusy(false);
		}
	}

	async function removeMember(member: MemberView) {
		if (!group) return;
		const who = member.email ?? member.userName ?? member.id;
		// The same question as on a person's Groups tab: one act, one wording, from either side.
		const agreed = await confirm('userGroup.member.remove', {
			target: who,
			consequences: [
				`Their next token no longer names ${group.displayName} in its groups claim.`
			]
		});
		if (!agreed) return;
		const result = await request(
			'DELETE',
			`${api}/members/${encodeURIComponent(member.id)}`
		);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done(`${who} removed from ${group.displayName}.`);
		await reloadAll();
	}

	async function handOverStep(
		commit: boolean
	): Promise<PreviewStep<HandOverPreview>> {
		const result = await request<GroupView>('POST', `${api}/connection`, {
			connectionId: target,
			...(commit && preview ? { confirm: true, expect: preview.expect } : {})
		});
		if (result.ok) {
			return {
				kind: 'done',
				text: `User group ${group?.displayName ?? ''} handed over to ${
					connections.find((c) => c.id === target)?.displayName ??
					'the directory'
				}.`
			};
		}
		if (result.status === 409 && isHandOverPreview(result.error)) {
			setTyped('');
			return { kind: 'preview', preview: result.error };
		}
		return { kind: 'failed', result };
	}

	const blocked = preview !== null && preview.expect.foreign > 0;
	const handOverReady =
		target !== undefined &&
		(preview === null ||
			(!blocked && group !== null && typed.trim() === group.displayName));

	return (
		<>
			<PageHeader
				crumbs={[
					{ label: 'Buckets', href: '/admin/buckets' },
					{ label: bucket?.name ?? '…', href: bucketHref(bucketId) },
					{ label: 'User groups', href: listHref },
					{ label: group?.displayName ?? '…' }
				]}
				title={group?.displayName ?? '…'}
				tags={
					keptByDirectory ? (
						<Tag color="purple">
							Managed by {keeper?.displayName ?? group.provisionedBy}
						</Tag>
					) : undefined
				}
				meta={
					group
						? `${group.memberCount} ${group.memberCount === 1 ? 'member' : 'members'} · applications receive this name in the groups claim`
						: undefined
				}
				actions={
					group && can.edit && !keptByDirectory ? (
						<Button onClick={() => setRenaming(true)}>Rename…</Button>
					) : undefined
				}
			/>
			{loading && !group && <Skeleton active />}
			{group && keptByDirectory && (
				<Alert
					type="info"
					showIcon
					style={{ marginBottom: 16 }}
					title={
						<>
							This group is kept by{' '}
							{keeper ? (
								<Link href={connectionHref(bucketId, keeper.id)}>
									{keeper.displayName}
								</Link>
							) : (
								'a directory'
							)}
							. Change its name and members in the directory.
						</>
					}
				/>
			)}
			{group && (
				<Flex
					vertical
					gap={16}
				>
					<Card title="Members">
						{membersEditable && (
							<Flex
								gap={8}
								style={{ marginBottom: 12 }}
							>
								<div style={{ flex: 1 }}>
									<UserSearchSelect
										bucketId={bucketId}
										value={adding}
										onChange={(ids) => setAdding(ids.slice(0, MAX_ADD))}
										placeholder="Find people by email to add"
									/>
								</div>
								<Button
									type="primary"
									loading={addBusy}
									disabled={adding.length === 0}
									onClick={() => void addMembers()}
								>
									{adding.length > 1 ? `Add ${adding.length} people` : 'Add'}
								</Button>
							</Flex>
						)}
						<Table<MemberView>
							rowKey="id"
							size="small"
							loading={membersLoading}
							dataSource={members}
							pagination={{
								current: memberPage,
								pageSize: PAGE,
								total: memberTotal,
								hideOnSinglePage: true,
								showSizeChanger: false,
								onChange: (page) => {
									setMembersLoading(true);
									void fetchMembers(page);
								}
							}}
							locale={{
								emptyText: membersLoading ? ' ' : 'Nobody is in this group yet.'
							}}
							columns={[
								{
									title: 'Person',
									render: (_, m) => (
										<Link href={userHref(bucketId, m.id)}>
											{m.email ?? m.userName ?? m.id}
										</Link>
									)
								},
								...(membersEditable
									? [
											{
												title: '',
												key: 'remove',
												width: 120,
												render: (_: unknown, m: MemberView) => (
													<Button
														size="small"
														onClick={() => void removeMember(m)}
													>
														Remove…
													</Button>
												)
											}
										]
									: [])
							]}
						/>
					</Card>

					{can.edit && !keptByDirectory && (
						<Card
							title="Danger zone"
							styles={{ header: { color: 'var(--ant-color-error)' } }}
						>
							<Flex
								vertical
								gap={16}
							>
								{connections.length > 0 && (
									<Flex
										justify="space-between"
										align="center"
										gap={12}
										wrap
									>
										<div>
											<Typography.Text strong>
												Hand over to a directory
											</Typography.Text>
											<br />
											<Typography.Text type="secondary">
												From then on only the directory renames it and changes
												its members. It can't be handed back from the console.
											</Typography.Text>
										</div>
										<Button
											danger
											onClick={() => {
												setTarget(undefined);
												setPreview(null);
												setTyped('');
												setHandOver(true);
											}}
										>
											Hand over to a directory…
										</Button>
									</Flex>
								)}
								<Flex
									justify="space-between"
									align="center"
									gap={12}
									wrap
								>
									<div>
										<Typography.Text strong>Delete user group</Typography.Text>
										<br />
										<Typography.Text type="secondary">
											Its members lose whatever applications grant for it. The
											people are kept.
										</Typography.Text>
									</div>
									<Button
										danger
										onClick={() =>
											void deleteGroup(group).then((done) => {
												if (done) void navigate(listHref);
											})
										}
									>
										Delete user group…
									</Button>
								</Flex>
							</Flex>
						</Card>
					)}
				</Flex>
			)}

			<RenameGroupModal
				bucketId={bucketId}
				group={renaming ? group : null}
				onClose={() => setRenaming(false)}
				onRenamed={() => void fetchGroup()}
			/>

			<PreviewConfirm<HandOverPreview>
				open={handOver}
				title={`Hand ${group?.displayName ?? ''} over to a directory?`}
				nextText="Check members"
				commitText="Hand over"
				danger
				ready={handOverReady}
				preview={preview}
				onPreview={setPreview}
				step={handOverStep}
				onClose={() => setHandOver(false)}
				onDone={() => {
					setHandOver(false);
					void reloadAll(1);
				}}
				renderPreview={(p) => (
					<Flex
						vertical
						gap={12}
						style={{ marginTop: 12 }}
					>
						<ul style={{ margin: 0, paddingLeft: 20 }}>
							{p.consequences.map((line) => (
								<li key={line}>{line}</li>
							))}
						</ul>
						{p.expect.foreign > 0 ? (
							<Alert
								type="error"
								showIcon
								title={`${p.expect.foreign} ${p.expect.foreign === 1 ? 'member is' : 'members are'} not managed by this directory`}
								description={
									<Flex
										vertical
										gap={4}
									>
										<span>
											Remove them from the group, or have the directory take
											them over, first.
										</span>
										{p.blockers.map((b) => (
											<Link
												key={b.id}
												href={userHref(bucketId, b.id)}
											>
												{b.email ?? b.id}
											</Link>
										))}
										{p.expect.foreign > p.blockers.length && (
											<Typography.Text type="secondary">
												and {p.expect.foreign - p.blockers.length} more
											</Typography.Text>
										)}
									</Flex>
								}
							/>
						) : (
							<Flex
								vertical
								gap={4}
							>
								<Typography.Text>
									Type{' '}
									<Typography.Text strong>{group?.displayName}</Typography.Text>{' '}
									to confirm
								</Typography.Text>
								<Input
									aria-label="Group name"
									autoComplete="off"
									value={typed}
									onChange={(e) => setTyped(e.target.value)}
								/>
							</Flex>
						)}
					</Flex>
				)}
			>
				<Flex
					vertical
					gap={4}
				>
					<Typography.Text>Which directory takes it over?</Typography.Text>
					<Select
						aria-label="Provisioning connection"
						value={target}
						onChange={(v: string) => {
							setTarget(v);
							setPreview(null);
						}}
						options={connections.map((c) => ({
							label: c.displayName,
							value: c.id
						}))}
						style={{ width: '100%' }}
					/>
				</Flex>
			</PreviewConfirm>
		</>
	);
}
