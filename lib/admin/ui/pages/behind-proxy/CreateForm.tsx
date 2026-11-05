import { useEffect, useState } from 'react';
import {
	Button,
	Divider,
	Flex,
	Form,
	Input,
	Modal,
	Radio,
	Select,
	Typography
} from 'antd';
import type { FormInstance } from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { request } from '../../frame/request.js';
import { useFeedback } from '../../frame/feedback.js';
import { useNavigate } from '../../frame/router.js';
import { behindProxyHref } from '../../frame/routes.js';
import { groupsApi, type GroupView } from '../groups/groupShared.js';
import { canonicalAddress } from '../../../../behind_proxy/address.js';
import {
	PROXY_KINDS,
	type ProxyKind
} from '../../../../behind_proxy/recipes.js';
import { behindProxyApi, PROXY_LABELS, type AppView } from './appView.js';

export interface CreateValues {
	name: string;
	address: string;
	rootGroups: string[];
	proxyKind: ProxyKind;
}

const INITIAL: Partial<CreateValues> = { proxyKind: 'caddy', rootGroups: [] };

const ADDRESS_PROBLEMS = {
	not_a_url:
		'Enter the address people open, such as https://grafana.example.com.',
	not_https: 'The address must start with https://.',
	userinfo: 'Leave out a user name or password.',
	ip_literal: 'Use a host name, not an IP address.',
	no_host: 'The address must name a host.'
} as const;

/* What the server will store for what was typed: only the origin, with the path dropped and said so. */
function addressNote(typed: string | undefined): string | null {
	if (!typed?.trim()) return null;
	const canonical = canonicalAddress(typed);
	if ('problem' in canonical) return null;
	return canonical.dropped
		? `Stored as ${canonical.address}: the path is dropped, since the app is the whole host. Paths get their own rules on the Access tab.`
		: `Stored as ${canonical.address}.`;
}

/*
 * The fields of a new app behind the proxy (specs/122 FR-031, UX Ф3): everything without which nobody could get
 * in on the first try. Who can open it is required, because an app with no group at its root would be a door
 * nobody may open; a group can be made here, without leaving the form. Used both as the second step of "New
 * application" and in the window of the table's own button, so the two ask the same questions the same way.
 */
export function CreateFields({
	bucketId,
	form,
	onBusy,
	onCreated
}: {
	bucketId: string;
	form: FormInstance<CreateValues>;
	onBusy: (busy: boolean) => void;
	onCreated: () => void;
}) {
	const feedback = useFeedback();
	const navigate = useNavigate();
	const [groups, setGroups] = useState<GroupView[]>([]);
	const [newGroup, setNewGroup] = useState('');
	const [creatingGroup, setCreatingGroup] = useState(false);
	const typedAddress = Form.useWatch('address', form);
	const chosen = Form.useWatch('rootGroups', form) as string[] | undefined;

	useEffect(() => {
		void request<{ groups: GroupView[] }>('GET', groupsApi(bucketId)).then(
			(result) => {
				if (result.ok) setGroups(result.data.groups);
			}
		);
	}, [bucketId]);

	async function addGroup() {
		const displayName = newGroup.trim();
		if (!displayName) return;
		setCreatingGroup(true);
		try {
			const result = await request<GroupView>('POST', groupsApi(bucketId), {
				displayName
			});
			if (!result.ok) {
				feedback.failed(result);
				return;
			}
			feedback.done(`Group ${displayName} created.`);
			setGroups((current) => [...current, result.data]);
			form.setFieldValue('rootGroups', [
				...((form.getFieldValue('rootGroups') as string[] | undefined) ?? []),
				result.data.id
			]);
			setNewGroup('');
		} finally {
			setCreatingGroup(false);
		}
	}

	async function create(values: CreateValues) {
		onBusy(true);
		try {
			const result = await request<AppView>('POST', behindProxyApi(bucketId), {
				name: values.name.trim(),
				address: values.address.trim(),
				proxyKind: values.proxyKind,
				rootGroups: values.rootGroups
			});
			if (!result.ok) {
				feedback.failed(result, form);
				return;
			}
			feedback.done(`${result.data.name} created.`);
			onCreated();
			void navigate(behindProxyHref(bucketId, result.data.id));
		} finally {
			onBusy(false);
		}
	}

	const empty = groups.filter(
		(group) => chosen?.includes(group.id) && group.memberCount === 0
	);
	const note = addressNote(typedAddress);

	return (
		<Form<CreateValues>
			form={form}
			layout="vertical"
			initialValues={INITIAL}
			preserve={false}
			onFinish={(values) => void create(values)}
		>
			<Form.Item
				name="name"
				label="Name"
				rules={[
					{ required: true, whitespace: true, message: 'Name the app.' },
					{ max: 100, message: 'At most 100 characters.' }
				]}
			>
				<Input placeholder="Grafana" />
			</Form.Item>
			<Form.Item
				name="address"
				label="Its address"
				rules={[
					{ required: true, message: 'Enter the address people open.' },
					{
						validator: async (_rule, value: string | undefined) => {
							if (!value?.trim()) return;
							const canonical = canonicalAddress(value);
							if ('problem' in canonical) {
								throw new Error(ADDRESS_PROBLEMS[canonical.problem]);
							}
						}
					}
				]}
				extra={
					note ??
					'Paste it from the browser. A port other than 443 is kept, as it makes a different address; a path is dropped.'
				}
			>
				<Input placeholder="https://grafana.example.com" />
			</Form.Item>
			<Form.Item
				name="rootGroups"
				label="Who can open it"
				rules={[
					{
						required: true,
						type: 'array',
						min: 1,
						message: 'Choose at least one group.'
					}
				]}
				extra={
					empty.length > 0
						? `${empty.map((group) => group.displayName).join(', ')} ${empty.length === 1 ? 'has' : 'have'} no members yet: nobody gets in until you add people.`
						: 'People sign in to this project and must be in one of these groups. Other paths can be opened to others on the Access tab.'
				}
			>
				<Select
					mode="multiple"
					placeholder="Choose groups"
					showSearch={{ optionFilterProp: 'label' }}
					options={groups.map((group) => ({
						value: group.id,
						label: group.displayName
					}))}
					popupRender={(menu) => (
						<>
							{menu}
							<Divider style={{ margin: '8px 0' }} />
							<Flex
								gap={8}
								style={{ padding: '0 8px 4px' }}
							>
								<Input
									aria-label="New group name"
									placeholder="New group…"
									value={newGroup}
									onChange={(e) => setNewGroup(e.target.value)}
									onKeyDown={(e) => e.stopPropagation()}
								/>
								<Button
									icon={<PlusOutlined />}
									loading={creatingGroup}
									disabled={!newGroup.trim()}
									onClick={() => void addGroup()}
								>
									Create group
								</Button>
							</Flex>
						</>
					)}
				/>
			</Form.Item>
			<Form.Item
				name="proxyKind"
				label="Your proxy"
				extra="Only decides which configuration Connect shows first; all three work."
			>
				<Radio.Group
					optionType="button"
					options={PROXY_KINDS.map((kind) => ({
						value: kind,
						label: PROXY_LABELS[kind]
					}))}
				/>
			</Form.Item>
		</Form>
	);
}

/* The table's own "New app behind your proxy": the same fields, in a window of their own. */
export function NewBehindProxyModal({
	bucketId,
	open,
	onClose
}: {
	bucketId: string;
	open: boolean;
	onClose: () => void;
}) {
	const [form] = Form.useForm<CreateValues>();
	const [busy, setBusy] = useState(false);
	return (
		<Modal
			title="New app behind your proxy"
			open={open}
			okText="Create app"
			confirmLoading={busy}
			onOk={() => form.submit()}
			onCancel={onClose}
			mask={{ closable: false }}
			keyboard={false}
			destroyOnHidden
		>
			<Typography.Paragraph type="secondary">
				A web app with no sign-in of its own. Caddy, Traefik or nginx asks this
				project who may open it.
			</Typography.Paragraph>
			<CreateFields
				bucketId={bucketId}
				form={form}
				onBusy={setBusy}
				onCreated={onClose}
			/>
		</Modal>
	);
}
