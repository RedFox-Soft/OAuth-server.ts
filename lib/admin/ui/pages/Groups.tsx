import { useCallback, useEffect, useState } from 'react';
import { Button, Form, Input, Modal, Table, Tag } from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { groupLabel } from '../../groups/label.js';
import { PageHeader } from '../frame/PageHeader.js';
import { request } from '../frame/request.js';
import { useFeedback } from '../frame/feedback.js';
import { Link, useNavigate, useRoute } from '../frame/router.js';
import { groupHref } from '../frame/routes.js';
import { EmptyState, LoadFailed } from '../frame/states.js';
import { meCan, useMe } from '../frame/me.js';

interface GroupMember {
	userId: string;
	role: 'owner' | 'member';
}

/* A row of `GET /admin/api/groups`; `owns` counts what membership reaches (specs/085). */
interface Group {
	_id: string;
	name: string;
	kind: 'personal' | 'regular' | 'system';
	members: GroupMember[];
	owns?: { buckets: number };
}

function plural(n: number, one: string, many: string): string {
	return `${String(n)} ${n === 1 ? one : many}`;
}

/*
 * The administrator groups the operator can open. Each opens its own page (specs/085), where members,
 * invitations and deletion live; this list only finds a group and creates one.
 */
export function Groups({ currentUserId }: { currentUserId: string | null }) {
	const feedback = useFeedback();
	const navigate = useNavigate();
	const { query } = useRoute();
	const { me } = useMe();
	const mayCreate = meCan(me).createGroup;
	const [groups, setGroups] = useState<Group[]>([]);
	const [loading, setLoading] = useState(true);
	const [failed, setFailed] = useState<string | null>(null);
	// A personal group's page offers "New group", which lands here with the dialog open.
	const [open, setOpen] = useState(query.get('new') === '1');
	const [form] = Form.useForm<{ name: string }>();

	// Every state write follows an await, so the mount effect calls this without setting
	// `loading` first; `load` is the reload, which does.
	const fetchGroups = useCallback(async () => {
		try {
			const result = await request<Group[]>('GET', '/admin/api/groups');
			if (!result.ok) {
				setFailed(result.error.message);
				return;
			}
			setFailed(null);
			setGroups(result.data);
		} finally {
			setLoading(false);
		}
	}, []);
	function load() {
		setLoading(true);
		return fetchGroups();
	}

	useEffect(() => {
		void fetchGroups();
	}, [fetchGroups]);

	async function onCreate(values: { name: string }) {
		const result = await request<Group>('POST', '/admin/api/groups', values);
		if (!result.ok) {
			feedback.failed(result, form);
			return;
		}
		feedback.done(`Group ${values.name} created.`);
		setOpen(false);
		form.resetFields();
		void navigate(groupHref(result.data._id));
	}

	/*
	 * Another administrator's personal group is left out: a super administrator would otherwise see one
	 * indistinguishable row per administrator on the instance. The operator's own is listed, said to be
	 * theirs alone, so it is not mistaken for a place to share things.
	 *
	 * Filtered here rather than in `GET /admin/api/groups`, which is also the MCP `group_list` tool and the
	 * answer to "which groups does this account belong to".
	 */
	const visible = groups.filter(
		(g) =>
			g.kind !== 'personal' || g.members.some((m) => m.userId === currentUserId)
	);
	const labelOf = (g: Group) =>
		g.kind === 'personal' ? 'Personal · Only you' : groupLabel(g);

	const newGroup = (
		<Button
			type="primary"
			icon={<PlusOutlined />}
			onClick={() => setOpen(true)}
		>
			New group
		</Button>
	);

	return (
		<>
			<PageHeader
				title="Groups"
				actions={mayCreate ? newGroup : undefined}
			/>
			{failed !== null ? (
				<LoadFailed
					reason={failed}
					onRetry={() => void load()}
				/>
			) : (
				<Table<Group>
					rowKey="_id"
					loading={loading}
					dataSource={visible}
					locale={{
						emptyText: (
							<EmptyState
								purpose="No groups yet. Create one to share user buckets with colleagues."
								create={mayCreate ? newGroup : undefined}
							/>
						)
					}}
					columns={[
						{
							title: 'Name',
							dataIndex: 'name',
							render: (_: string, g: Group) => (
								<Link href={groupHref(g._id)}>{labelOf(g)}</Link>
							)
						},
						{
							title: 'Kind',
							dataIndex: 'kind',
							render: (kind: Group['kind']) =>
								kind === 'regular' ? null : (
									<Tag>{kind === 'system' ? 'System' : 'Personal'}</Tag>
								)
						},
						{
							title: 'Members',
							dataIndex: 'members',
							render: (members: GroupMember[]) => members.length
						},
						{
							title: 'Owns',
							key: 'owns',
							render: (_: unknown, g: Group) =>
								g.owns ? plural(g.owns.buckets, 'bucket', 'buckets') : '—'
						}
					]}
				/>
			)}
			<Modal
				open={open}
				title="New group"
				onCancel={() => setOpen(false)}
				onOk={() => form.submit()}
			>
				<Form<{ name: string }>
					form={form}
					layout="vertical"
					scrollToFirstError
					onFinish={onCreate}
				>
					<Form.Item
						label="Name"
						name="name"
						rules={[{ required: true }]}
						extra="Usually a company or team name. You become its first owner."
					>
						<Input />
					</Form.Item>
				</Form>
			</Modal>
		</>
	);
}
