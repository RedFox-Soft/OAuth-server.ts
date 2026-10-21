import { useCallback, useEffect, useState } from 'react';
import {
	Alert,
	Button,
	Card,
	Drawer,
	Empty,
	Flex,
	Form,
	Input,
	Radio,
	Select,
	Switch,
	Table,
	Tag,
	Typography
} from 'antd';
import { DeleteOutlined, PlusOutlined } from '@ant-design/icons';
import { request } from '../frame/request.js';
import { useFeedback } from '../frame/feedback.js';
import { useConfirm } from '../frame/confirm.js';
import { Link } from '../frame/router.js';
import type { GroupView } from './groups/groupShared.js';

const TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';

/* What the pickers need of a project application: how to name it, and whether it may ask at all. */
interface ApplicationChoice {
	clientId: string;
	clientName?: string;
	grantTypes: string[];
	tokenEndpointAuthMethod: string;
}

function choiceOf(application: ApplicationChoice) {
	return {
		value: application.clientId,
		label: application.clientName
			? `${application.clientName} (${application.clientId})`
			: application.clientId
	};
}

/*
 * The outside authorization servers a project vouches for its people to with ID-JAGs (specs/108 story 2): the
 * issuing side of MCP enterprise-managed authorization. Every rule is the server's; this panel only edits the
 * record and shows what the server said when it refuses.
 */

interface OutsideServerView {
	id: string;
	issuer: string;
	displayName: string;
	applications: { clientId: string; externalClientId?: string }[];
	rules: {
		appliesTo: 'everyone' | { groups: { id: string; name: string | null }[] };
		apis: { identifier: string; scopes: string[] }[];
	}[];
	signInApplication: string | null;
	includeEmail: boolean;
	lastUsedAt: number | null;
}

interface RuleForm {
	who: 'everyone' | 'groups';
	groups?: string[];
	apis: { identifier: string; scopes?: string[] }[];
}

interface ConnectionForm {
	issuer: string;
	displayName: string;
	applications: { clientId: string; externalClientId?: string }[];
	rules: RuleForm[];
	signInApplication?: string;
	includeEmail: boolean;
}

function formOf(view: OutsideServerView): ConnectionForm {
	return {
		issuer: view.issuer,
		displayName: view.displayName,
		applications: view.applications,
		rules: view.rules.map((rule) => ({
			who: rule.appliesTo === 'everyone' ? 'everyone' : 'groups',
			groups:
				rule.appliesTo === 'everyone'
					? []
					: rule.appliesTo.groups.map((group) => group.id),
			apis: rule.apis
		})),
		signInApplication: view.signInApplication ?? undefined,
		includeEmail: view.includeEmail
	};
}

function bodyOf(form: ConnectionForm, editing: boolean) {
	return {
		...(editing ? {} : { issuer: form.issuer.trim() }),
		displayName: form.displayName,
		applications: form.applications.map(({ clientId, externalClientId }) => ({
			clientId: clientId.trim(),
			...(externalClientId?.trim()
				? { externalClientId: externalClientId.trim() }
				: {})
		})),
		rules: form.rules.map((rule) => ({
			appliesTo:
				rule.who === 'everyone' ? 'everyone' : { groups: rule.groups ?? [] },
			apis: rule.apis.map(({ identifier, scopes }) => ({
				identifier: identifier.trim(),
				scopes: scopes ?? []
			}))
		})),
		...(form.signInApplication?.trim()
			? { signInApplication: form.signInApplication.trim() }
			: editing
				? { signInApplication: null }
				: {}),
		includeEmail: form.includeEmail
	};
}

const EMPTY: ConnectionForm = {
	issuer: '',
	displayName: '',
	applications: [{ clientId: '' }],
	rules: [{ who: 'everyone', apis: [{ identifier: '', scopes: [] }] }],
	includeEmail: true
};

export function OutsideServersPanel({
	bucketId,
	canEdit,
	exchangeOn
}: {
	bucketId: string;
	canEdit: boolean;
	exchangeOn: boolean;
}) {
	const base = `/admin/api/projects/${encodeURIComponent(bucketId)}`;
	const feedback = useFeedback();
	const confirm = useConfirm();
	const [servers, setServers] = useState<OutsideServerView[] | null>(null);
	const [loaded, setLoaded] = useState(false);
	const [groups, setGroups] = useState<GroupView[]>([]);
	const [applications, setApplications] = useState<ApplicationChoice[]>([]);
	const [editing, setEditing] = useState<OutsideServerView | 'new' | null>(
		null
	);

	// Every state write follows an await, so the mount effect calls this without setting anything first.
	const fetchAll = useCallback(async () => {
		try {
			const [list, groupList, clientList] = await Promise.all([
				request<OutsideServerView[]>(
					'GET',
					`${base}/outside-authorization-servers`
				),
				request<{ groups: GroupView[] }>('GET', `${base}/groups`),
				request<ApplicationChoice[]>('GET', `${base}/clients`)
			]);
			if (list.ok) setServers(list.data);
			else feedback.failed(list);
			if (groupList.ok) setGroups(groupList.data.groups);
			if (clientList.ok) setApplications(clientList.data);
		} finally {
			setLoaded(true);
		}
	}, [base, feedback]);
	useEffect(() => {
		void fetchAll();
	}, [fetchAll]);
	const load = () => void fetchAll();

	async function remove(server: OutsideServerView) {
		const agreed = await confirm('outsideServer.delete', {
			target: server.issuer,
			consequences: [
				'Agents stop getting ID-JAGs for this server at once.',
				'ID-JAGs already issued live out their few minutes.'
			]
		});
		if (!agreed) return;
		const result = await request(
			'DELETE',
			`${base}/outside-authorization-servers/${encodeURIComponent(server.id)}`
		);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done(`${server.displayName} disconnected.`);
		load();
	}

	return (
		<Card
			title="Outside authorization servers"
			extra={
				canEdit && (
					<Button
						type="primary"
						icon={<PlusOutlined />}
						onClick={() => setEditing('new')}
					>
						Connect
					</Button>
				)
			}
		>
			{!exchangeOn && (
				<Alert
					type="info"
					showIcon
					style={{ marginBottom: 16 }}
					title="Token exchange is turned off for this instance"
					description={
						<>
							Connections can be prepared, but no ID-JAG is issued until it is
							turned on in <Link href="/admin/settings">Settings → Grants</Link>
							.
						</>
					}
				/>
			)}
			{servers && servers.length === 0 ? (
				<Empty description="Let your users' agents reach MCP servers run by others. Connect the authorization server of an outside MCP server, choose which of your applications may ask and who may get what." />
			) : (
				<Table<OutsideServerView>
					rowKey="id"
					loading={!loaded}
					dataSource={servers ?? []}
					pagination={false}
					columns={[
						{
							title: 'Name',
							dataIndex: 'displayName',
							render: (name: string, server) =>
								canEdit ? (
									<Typography.Link onClick={() => setEditing(server)}>
										{name}
									</Typography.Link>
								) : (
									name
								)
						},
						{
							title: 'Issuer',
							dataIndex: 'issuer',
							render: (issuer: string) => (
								<Typography.Text code>{issuer}</Typography.Text>
							)
						},
						{
							title: 'Applications',
							render: (_, server) => server.applications.length
						},
						{
							title: 'Last used',
							dataIndex: 'lastUsedAt',
							render: (at: number | null) =>
								at === null ? 'Never' : new Date(at * 1000).toLocaleString()
						},
						...(canEdit
							? [
									{
										title: '',
										key: 'actions',
										render: (_: unknown, server: OutsideServerView) => (
											<Button
												danger
												size="small"
												icon={<DeleteOutlined />}
												aria-label={`Disconnect ${server.displayName}`}
												onClick={() => void remove(server)}
											/>
										)
									}
								]
							: [])
					]}
				/>
			)}
			{editing !== null && (
				<ConnectionEditor
					base={base}
					server={editing === 'new' ? null : editing}
					groups={groups}
					applications={applications}
					onClose={() => setEditing(null)}
					onSaved={() => {
						setEditing(null);
						load();
					}}
				/>
			)}
		</Card>
	);
}

function ConnectionEditor({
	base,
	server,
	groups,
	applications,
	onClose,
	onSaved
}: {
	base: string;
	server: OutsideServerView | null;
	groups: GroupView[];
	applications: ApplicationChoice[];
	onClose: () => void;
	onSaved: () => void;
}) {
	const feedback = useFeedback();
	const confirm = useConfirm();
	const [form] = Form.useForm<ConnectionForm>();
	const [saving, setSaving] = useState(false);
	const [refusal, setRefusal] = useState<string | null>(null);
	const editing = server !== null;
	const knownGroups = new Set(groups.map((group) => group.id));
	// The server refuses any other; listing only these keeps the refusal for a real mistake.
	const asking = applications
		.filter(
			(application) =>
				application.tokenEndpointAuthMethod !== 'none' &&
				application.grantTypes.includes(TOKEN_EXCHANGE)
		)
		.map(choiceOf);

	async function save(values: ConnectionForm) {
		const question = {
			target: values.issuer,
			consequences: [
				`This project will vouch for its people to ${values.issuer}.`,
				'The applications you allow can then get tokens there for those people, with no consent screen.'
			]
		};
		const agreed = editing
			? await confirm('outsideServer.edit', question)
			: await confirm('outsideServer.connect', question);
		if (!agreed) return;
		setSaving(true);
		try {
			const result = await request(
				editing ? 'PATCH' : 'POST',
				editing
					? `${base}/outside-authorization-servers/${encodeURIComponent(server.id)}`
					: `${base}/outside-authorization-servers`,
				bodyOf(values, editing)
			);
			if (!result.ok) {
				if (result.status >= 500) feedback.failed(result);
				else setRefusal(result.error.message);
				return;
			}
			feedback.done(`${values.displayName} saved.`);
			onSaved();
		} finally {
			setSaving(false);
		}
	}

	return (
		<Drawer
			open
			size="large"
			title={
				editing
					? `Edit ${server.displayName}`
					: 'Connect an outside authorization server'
			}
			onClose={onClose}
			extra={
				<Button
					type="primary"
					loading={saving}
					onClick={() => form.submit()}
				>
					Save
				</Button>
			}
		>
			{refusal && (
				<Alert
					type="error"
					showIcon
					style={{ marginBottom: 16 }}
					title="Not saved"
					description={refusal}
				/>
			)}
			<Form<ConnectionForm>
				form={form}
				layout="vertical"
				initialValues={server ? formOf(server) : EMPTY}
				onFinish={(values) => void save(values)}
				onValuesChange={() => setRefusal(null)}
			>
				<Form.Item
					name="issuer"
					label="Issuer"
					extra={
						editing
							? "Can't be changed: connect the other server instead."
							: 'The authorization server of the outside MCP server, as its metadata names it.'
					}
					rules={[{ required: true, message: 'Enter the issuer' }]}
				>
					<Input
						disabled={editing}
						placeholder="https://auth.tickets.example"
					/>
				</Form.Item>
				<Form.Item
					name="displayName"
					label="Name"
					rules={[{ required: true, message: 'Name the connection' }]}
				>
					<Input placeholder="Tickets" />
				</Form.Item>

				<Typography.Title level={5}>Applications that may ask</Typography.Title>
				<Form.List name="applications">
					{(fields, { add, remove }) => (
						<Flex
							vertical
							gap={8}
						>
							{fields.map((field) => (
								<Flex
									key={field.key}
									gap={8}
									align="start"
								>
									<Form.Item
										name={[field.name, 'clientId']}
										rules={[
											{ required: true, message: 'Choose an application' }
										]}
										style={{ flex: 1, marginBottom: 0 }}
										extra="Applications that authenticate and carry the token exchange grant"
									>
										<Select
											aria-label="Application"
											placeholder="Application"
											showSearch={{ optionFilterProp: 'label' }}
											options={asking}
										/>
									</Form.Item>
									<Form.Item
										name={[field.name, 'externalClientId']}
										style={{ flex: 1, marginBottom: 0 }}
										extra="Client ID at this server (not needed when the application's id is a URL)"
									>
										<Input aria-label="Client ID at this server" />
									</Form.Item>
									<Button
										aria-label="Remove application"
										icon={<DeleteOutlined />}
										onClick={() => remove(field.name)}
									/>
								</Flex>
							))}
							<Button
								icon={<PlusOutlined />}
								onClick={() => add({ clientId: '' })}
							>
								Add application
							</Button>
						</Flex>
					)}
				</Form.List>

				<Typography.Title
					level={5}
					style={{ marginTop: 24 }}
				>
					Who may get what
				</Typography.Title>
				<Form.List name="rules">
					{(fields, { add, remove }) => (
						<Flex
							vertical
							gap={12}
						>
							{fields.map((field) => (
								<Card
									key={field.key}
									size="small"
									extra={
										<Button
											size="small"
											aria-label="Remove rule"
											icon={<DeleteOutlined />}
											onClick={() => remove(field.name)}
										/>
									}
								>
									<Form.Item
										name={[field.name, 'who']}
										label="Who"
									>
										<Radio.Group>
											<Radio value="everyone">Everyone in the project</Radio>
											<Radio value="groups">Members of groups</Radio>
										</Radio.Group>
									</Form.Item>
									<Form.Item
										noStyle
										shouldUpdate
									>
										{({ getFieldValue }) =>
											getFieldValue(['rules', field.name, 'who']) ===
												'groups' && (
												<Form.Item
													name={[field.name, 'groups']}
													label="Groups"
												>
													<Select
														mode="multiple"
														options={groups.map((group) => ({
															value: group.id,
															label: group.displayName
														}))}
														tagRender={({
															value,
															label,
															closable,
															onClose
														}) => (
															<Tag
																color={
																	knownGroups.has(String(value))
																		? undefined
																		: 'red'
																}
																closable={closable}
																onClose={onClose}
															>
																{knownGroups.has(String(value))
																	? label
																	: 'Deleted group'}
															</Tag>
														)}
													/>
												</Form.Item>
											)
										}
									</Form.Item>
									<Form.List name={[field.name, 'apis']}>
										{(apiFields, apis) => (
											<Flex
												vertical
												gap={8}
											>
												{apiFields.map((api) => (
													<Flex
														key={api.key}
														gap={8}
														align="start"
													>
														<Form.Item
															name={[api.name, 'identifier']}
															rules={[
																{
																	required: true,
																	message: 'Enter the MCP server'
																}
															]}
															style={{ flex: 2, marginBottom: 0 }}
														>
															<Input
																aria-label="MCP server"
																placeholder="https://mcp.tickets.example/"
															/>
														</Form.Item>
														<Form.Item
															name={[api.name, 'scopes']}
															style={{ flex: 1, marginBottom: 0 }}
														>
															<Select
																aria-label="Scopes"
																mode="tags"
																placeholder="Scopes"
															/>
														</Form.Item>
														<Button
															aria-label="Remove MCP server"
															icon={<DeleteOutlined />}
															onClick={() => apis.remove(api.name)}
														/>
													</Flex>
												))}
												<Button
													size="small"
													icon={<PlusOutlined />}
													onClick={() =>
														apis.add({ identifier: '', scopes: [] })
													}
												>
													Add MCP server
												</Button>
											</Flex>
										)}
									</Form.List>
								</Card>
							))}
							<Button
								icon={<PlusOutlined />}
								onClick={() =>
									add({
										who: 'everyone',
										apis: [{ identifier: '', scopes: [] }]
									})
								}
							>
								Add rule
							</Button>
						</Flex>
					)}
				</Form.List>

				<Typography.Title
					level={5}
					style={{ marginTop: 24 }}
				>
					Optional
				</Typography.Title>
				<Form.Item
					name="signInApplication"
					label="Application this server signs people in with"
					extra="Decides the identifier the server knows people by. Leave empty to use their own identifier here."
				>
					<Select
						allowClear
						showSearch={{ optionFilterProp: 'label' }}
						options={applications.map(choiceOf)}
					/>
				</Form.Item>
				<Form.Item
					name="includeEmail"
					label="Include verified email"
					valuePropName="checked"
				>
					<Switch />
				</Form.Item>
			</Form>
		</Drawer>
	);
}
