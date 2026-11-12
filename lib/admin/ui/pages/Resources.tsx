import { useCallback, useEffect, useState } from 'react';
import {
	Table,
	Button,
	Modal,
	Form,
	Input,
	InputNumber,
	Select,
	Space,
	Typography,
	Alert,
	Tag,
	Checkbox,
	Tooltip,
	Radio,
	type FormInstance
} from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { SCOPE_DESCRIPTION_MAX_LENGTH } from '../../../resources/scopes.js';
import { request } from '../frame/request.js';
import { useFeedback } from '../frame/feedback.js';
import { useConfirm } from '../frame/confirm.js';
import { AreaToolbar } from '../frame/AreaToolbar.js';
import { RowActions } from '../frame/RowActions.js';
import { useQueryOffer } from '../frame/queryOffer.js';
import { Link, useNavigate } from '../frame/router.js';
import { apiHref } from '../frame/routes.js';
import { EmptyState, LoadFailed } from '../frame/states.js';
import { atLimit, type PlanView } from '../planText.js';
import {
	applicationName,
	type ExchangeCandidate
} from './applications/exchange.js';
import {
	everyMinutes,
	ResourceSignInFields,
	signInEveryText,
	type EveryChoice,
	type EveryUnit
} from './resources/ResourceSignInFields.js';
import { useCodeConsent, withConsent } from './applications/codeConsent.js';
import { VouchingCell } from './resources/vouching.js';
import {
	CHECKED_BY_OPTIONS,
	describedScopes,
	describeWindow,
	KIND_OPTIONS,
	removalConsequences,
	resourcesApi,
	scopeAdvice,
	splitScopes,
	TOKEN_FORMAT_OPTIONS,
	type CheckedBy,
	type DescriptionsInput,
	type ResourceView
} from './resources/resourceView.js';

/*
 * A bucket's APIs — its declared protected resources: the audiences this server will mint tokens for on
 * the bucket's behalf (specs/099). Each has a page of its own (specs/132); this is the list, and the form that
 * declares a new one, which states the scope-list warning and the revocation window for the reasons the API's
 * Settings tab gives.
 */

/* How agent hosts get a client identity here, from the project's own public configuration (spec 107). */
export interface AgentClients {
	urlClientIds: boolean;
	selfRegistration: 'open' | 'token' | 'off';
}

// Form.useWatch is typed as the field's value, but it answers undefined until the field registers.
function useWatched<K extends keyof FormValues>(
	form: FormInstance<FormValues>,
	name: K
): FormValues[K] | undefined {
	return Form.useWatch(name, form);
}

interface FormValues {
	identifier: string;
	name: string;
	scopes: string;
	/* Per scope, what it lets an app do and whether it only sees; keyed by the scope as typed above. */
	descriptions?: DescriptionsInput;
	tokenFormat: 'jwt' | 'opaque';
	// InputNumber answers null once the operator clears it.
	accessTokenTTL: number | null;
	trailingSlashSignificant: boolean;
	checkedBy: CheckedBy;
	requireCode?: boolean;
	every?: EveryChoice;
	customAmount?: number;
	customUnit?: EveryUnit;
}

const DEFAULT_VALUES: FormValues = {
	identifier: '',
	name: '',
	scopes: '',
	tokenFormat: 'jwt',
	accessTokenTTL: 900,
	trailingSlashSignificant: false,
	checkedBy: 'server',
	requireCode: false,
	every: 'off',
	customUnit: 'days'
};

/*
 * Where the bucket's declarations live (specs/085). An identifier is unique within a namespace: the bucket's
 * own when it has an address, the instance's root otherwise — shared with every other root-served bucket.
 */
function namespaceLine(
	bucketName: string,
	namespace: Namespace | null
): string {
	if (namespace === 'project') {
		return `Declared in ${bucketName}'s own namespace: an identifier must be unique within this project.`;
	}
	return "Declared in the instance's shared root namespace, which every project without an address of its own shares.";
}

type Namespace = 'project' | 'root';

/*
 * `canEdit` is the bucket's stated `edit` right. At the root namespace only a super administrator declares,
 * so the screen is writable there for them alone — the server refuses anyone else the same way.
 */
export function Resources({
	bucketId,
	bucketName,
	canEdit,
	superAdmin,
	plan,
	agentClients,
	onChanged
}: {
	bucketId: string;
	bucketName: string;
	canEdit: boolean;
	superAdmin: boolean;
	agentClients?: AgentClients;
	/* The plan the caller is held to (specs/102); null when nothing limits them. */
	plan?: PlanView | null;
	/* An API was declared or removed: the project's counts, and so its plan's use, changed. */
	onChanged?: () => void;
}) {
	const bucketBase = `/admin/api/projects/${encodeURIComponent(bucketId)}`;
	const base = resourcesApi(bucketId);
	const [namespace, setNamespace] = useState<Namespace | null>(null);
	const writable = canEdit && (namespace === 'project' || superAdmin);
	const [rows, setRows] = useState<ResourceView[]>([]);
	const [loading, setLoading] = useState(true);
	const [loadFailed, setLoadFailed] = useState<string | null>(null);
	const [open, setOpen] = useState(false);
	const [saving, setSaving] = useState(false);
	const [form] = Form.useForm<FormValues>();
	const feedback = useFeedback();
	const confirm = useConfirm();
	const navigate = useNavigate();
	const [applications, setApplications] = useState<ExchangeCandidate[]>([]);
	/*
	 * "My MCP server or API" in New application, and the guide's "Set this up", land here with ?declare=1 (spec 107):
	 * open the form once, when the New button would be offered.
	 */
	const offerDeclare = useQueryOffer('declare');
	const room = atLimit(plan, 'apis') === null;

	const scopesValue = useWatched(form, 'scopes') ?? '';
	const ttlValue = useWatched(form, 'accessTokenTTL') ?? 900;
	const formatValue = useWatched(form, 'tokenFormat') ?? 'jwt';
	const checkedByValue = useWatched(form, 'checkedBy') ?? 'server';
	const everyValue = useWatched(form, 'every');
	const signInConsent = useCodeConsent('api');

	// Every state write follows an await, so the mount effect calls this without setting
	// `loading` first; `load` is the reload, which does.
	const fetchResources = useCallback(
		() =>
			request<{ namespace: Namespace; resources: ResourceView[] }>(
				'GET',
				base
			).then((result) => {
				if (result.ok) {
					setNamespace(result.data.namespace);
					setRows(result.data.resources);
					setLoadFailed(null);
					const mayDeclare =
						canEdit && (result.data.namespace === 'project' || superAdmin);
					if (offerDeclare(mayDeclare && room) === '1') {
						form.resetFields();
						form.setFieldsValue(DEFAULT_VALUES);
						setOpen(true);
					}
				} else {
					setLoadFailed(result.error.message);
				}
				setLoading(false);
			}),
		[base, canEdit, superAdmin, room, offerDeclare, form]
	);
	function load() {
		setLoading(true);
		return fetchResources();
	}
	/*
	 * Reloads when the bucket changes and never on `load` identity — the list belongs to the bucket, not to
	 * the closure.
	 */
	useEffect(() => {
		void fetchResources();
	}, [fetchResources]);

	useEffect(() => {
		let live = true;
		void request<ExchangeCandidate[]>('GET', `${bucketBase}/clients`).then(
			(result) => {
				if (live && result.ok) setApplications(result.data);
			}
		);
		return () => {
			live = false;
		};
	}, [bucketBase]);

	function openCreateModal() {
		form.resetFields();
		form.setFieldsValue(DEFAULT_VALUES);
		setOpen(true);
	}

	async function submit(values: FormValues) {
		const scopes = splitScopes(values.scopes);
		const scopeDescriptions = describedScopes(scopes, values.descriptions);
		const requireCode = values.requireCode === true;
		const signInEveryMinutes = everyMinutes(values);
		const body = {
			identifier: values.identifier,
			name: values.name,
			scopes,
			...(Object.keys(scopeDescriptions).length ? { scopeDescriptions } : {}),
			tokenFormat: values.tokenFormat,
			accessTokenTTL: values.accessTokenTTL ?? undefined,
			trailingSlashSignificant: values.trailingSlashSignificant,
			checkedBy: values.checkedBy,
			...(requireCode ? { requireCode } : {}),
			...(signInEveryMinutes === null ? {} : { signInEveryMinutes })
		};
		setSaving(true);
		const result = await signInConsent(
			(consent) =>
				request<ResourceView>('POST', base, withConsent(body, consent)),
			values.name
		);
		setSaving(false);
		if (result === null) return;
		if (!result.ok) {
			feedback.failed(result, form);
			return;
		}
		feedback.done('Resource declared.');
		setOpen(false);
		onChanged?.();
		/* Declared, it is wired from its own page, as an app behind the proxy is (specs/132). */
		void navigate(apiHref(bucketId, result.data.identifier));
	}

	async function remove(row: ResourceView) {
		const clients = await request<
			{
				clientId: string;
				clientName?: string;
				registeredDynamically?: boolean;
			}[]
		>('GET', `${bucketBase}/clients`);
		const agreed = await confirm('resource.remove', {
			target: row.name,
			consequences: removalConsequences(clients.ok ? clients.data : null)
		});
		if (!agreed) return;
		const result = await request(
			'DELETE',
			resourcesApi(bucketId, row.identifier)
		);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done('Resource removed.');
		onChanged?.();
		await load();
	}

	const full = atLimit(plan, 'apis');
	const newResource = (
		<Tooltip title={full ?? undefined}>
			<Button
				type="primary"
				icon={<PlusOutlined />}
				disabled={full !== null}
				onClick={openCreateModal}
			>
				New resource
			</Button>
		</Tooltip>
	);

	return (
		<>
			{/*
			 * What a declared resource still needs before an agent host can reach it, stated once here
			 * rather than left to be discovered by a client that fails to connect.
			 *
			 * Not read from the settings API, unlike the Agent access screen: this page is reachable by a
			 * tenant administrator, who may not read instance settings. So it names the dependency
			 * without claiming to know the current value — which is honest, and is the same thing the
			 * guide says.
			 */}
			{agentClients && (
				<Alert
					type={
						agentClients.urlClientIds || agentClients.selfRegistration !== 'off'
							? 'info'
							: 'warning'
					}
					showIcon
					style={{ marginBottom: 16 }}
					title="How agent hosts get in"
					description={`Agent hosts that identify by a URL (Client ID Metadata Document): ${agentClients.urlClientIds ? 'accepted' : 'not accepted'}. Self-registration: ${agentClients.selfRegistration === 'open' ? 'open' : agentClients.selfRegistration === 'token' ? 'with an initial access token' : 'off'}. ${agentClients.urlClientIds || agentClients.selfRegistration !== 'off' ? 'Claude, Cursor and VS Code can connect to the APIs declared here.' : 'An agent host cannot get a client identity here; only applications created in this project can obtain tokens.'}`}
				/>
			)}

			<Typography.Paragraph type="secondary">
				{namespaceLine(bucketName, namespace)}
			</Typography.Paragraph>

			{writable ? (
				<AreaToolbar create={newResource} />
			) : (
				<Alert
					type="info"
					showIcon
					style={{ marginBottom: 16 }}
					title="These APIs are read-only to you"
					description={
						canEdit
							? "This project has no address of its own, so its APIs live in the instance's root namespace, where only a super administrator can declare or change them."
							: "Changing a project's APIs takes membership of the team that owns it."
					}
				/>
			)}

			{loadFailed !== null ? (
				<LoadFailed
					reason={loadFailed}
					onRetry={() => void load()}
				/>
			) : (
				<Table<ResourceView>
					rowKey="identifier"
					loading={loading}
					dataSource={rows}
					pagination={false}
					locale={{
						emptyText: (
							<EmptyState
								purpose="No APIs declared in this project yet. Declare one to have this server mint tokens for its audience."
								create={writable ? newResource : undefined}
							/>
						)
					}}
					columns={[
						{
							title: 'Resource',
							dataIndex: 'identifier',
							render: (identifier: string, row: ResourceView) => (
								<Space
									orientation="vertical"
									size={0}
								>
									<Link href={apiHref(bucketId, row.identifier)}>
										<strong>{row.name}</strong>
									</Link>
									<Typography.Text code>{identifier}</Typography.Text>
									{row.checkedBy === 'proxy' && (
										<Typography.Text type="secondary">
											Tokens checked by your proxy
										</Typography.Text>
									)}
									{(row.requireCode || row.signInEveryMinutes !== null) && (
										<Space size={4}>
											{row.requireCode && <Tag>Code required</Tag>}
											{row.signInEveryMinutes !== null && (
												<Tag>{signInEveryText(row.signInEveryMinutes)}</Tag>
											)}
										</Space>
									)}
									{row.exchangedBy && (
										<Typography.Text type="secondary">
											Tokens exchanged by{' '}
											{applicationName(row.exchangedBy, applications)}
										</Typography.Text>
									)}
								</Space>
							)
						},
						{
							title: 'Metadata',
							key: 'vouching',
							render: (_: unknown, row: ResourceView) => (
								<VouchingCell
									url={`${resourcesApi(bucketId, row.identifier)}/vouching`}
								/>
							)
						},
						{
							title: 'Scopes',
							dataIndex: 'scopes',
							render: (scopes: string[]) => (
								<Space
									size={[0, 4]}
									wrap
								>
									{scopes.map((scope) => (
										<Tag key={scope}>{scope}</Tag>
									))}
								</Space>
							)
						},
						{
							title: 'Token',
							dataIndex: 'tokenFormat',
							render: (format: 'jwt' | 'opaque') =>
								format === 'jwt' ? 'Self-contained' : 'Opaque'
						},
						{
							title: 'Lifetime',
							dataIndex: 'accessTokenTTL',
							render: (ttl: number, row: ResourceView) => (
								<Space
									orientation="vertical"
									size={0}
								>
									<span>{describeWindow(ttl)}</span>
									<Typography.Text type="secondary">
										{row.tokenFormat === 'jwt'
											? `revocation takes up to ${describeWindow(ttl)}`
											: 'revocation is immediate'}
									</Typography.Text>
								</Space>
							)
						},
						...(writable
							? [
									{
										title: '',
										key: 'actions',
										render: (_: unknown, row: ResourceView) => (
											<RowActions
												name={row.name}
												items={[
													{
														key: 'remove',
														label: 'Remove',
														group: 'danger',
														onClick: () => void remove(row)
													}
												]}
											/>
										)
									}
								]
							: [])
					]}
				/>
			)}

			<Modal
				open={open}
				title="New resource"
				onCancel={() => setOpen(false)}
				onOk={() => form.submit()}
				confirmLoading={saving}
				okText="Save"
				destroyOnHidden
			>
				<Form
					form={form}
					layout="vertical"
					initialValues={DEFAULT_VALUES}
					scrollToFirstError
					onFinish={(values) => void submit(values)}
				>
					<Form.Item
						name="identifier"
						label="Resource identifier"
						extra="The canonical URI of your MCP server, exactly as its clients will name it — for example https://mcp.example.com/mcp. No fragment. A trailing slash is dropped unless you mark it significant below."
						rules={[{ required: true, message: 'an identifier is required' }]}
					>
						<Input placeholder="https://mcp.example.com/mcp" />
					</Form.Item>
					{/*
					 * Off by default because the MCP specification asks clients for the slash-free form; on, the
					 * slash-free spelling becomes a different audience that is not declared.
					 */}
					<Form.Item
						name="trailingSlashSignificant"
						valuePropName="checked"
						extra="Only for a server that really serves a different resource at …/mcp/ than at …/mcp. When on, only the exact spelling is issued tokens."
					>
						<Checkbox>The trailing slash is significant</Checkbox>
					</Form.Item>
					<Form.Item
						name="checkedBy"
						label="Who checks tokens?"
						extra={
							checkedByValue === 'proxy'
								? 'Your proxy (Caddy, Traefik or nginx) asks this project about each request’s token, and this project serves the API’s metadata. The API needs an https identifier and no code of its own for this.'
								: 'Your API checks each token itself and serves its own metadata. Connect lists what it must check.'
						}
					>
						<Radio.Group
							options={CHECKED_BY_OPTIONS}
							optionType="button"
						/>
					</Form.Item>
					<Form.Item
						name="name"
						label="Name"
						rules={[{ required: true, message: 'a name is required' }]}
					>
						<Input placeholder="Acme MCP" />
					</Form.Item>
					<Form.Item
						name="scopes"
						label="Scopes it recognises"
						extra="Space-separated. The baseline for basic use, not a catalogue."
						rules={[{ required: true, message: 'at least one scope' }]}
					>
						<Input placeholder="mcp:tools-basic mcp:files-read" />
					</Form.Item>
					{splitScopes(scopesValue).length > 0 && (
						<Form.Item
							label="What each scope lets an app do"
							extra="Shown on the consent page after “The app will be able to”: a verb, then what it acts on — “run the service’s tools as you”. A scope left empty is shown only by its name, as not described."
						>
							<Space
								orientation="vertical"
								style={{ width: '100%' }}
							>
								{splitScopes(scopesValue).map((scope) => (
									<Space.Compact
										key={scope}
										style={{ width: '100%' }}
									>
										<Space.Addon>
											<Typography.Text code>{scope}</Typography.Text>
										</Space.Addon>
										<Form.Item
											name={['descriptions', scope, 'description']}
											noStyle
										>
											<Input
												maxLength={SCOPE_DESCRIPTION_MAX_LENGTH}
												placeholder="not described"
											/>
										</Form.Item>
										<Form.Item
											name={['descriptions', scope, 'kind']}
											noStyle
										>
											<Select
												options={KIND_OPTIONS}
												placeholder="Acts for the person"
												style={{ width: 190 }}
												allowClear
											/>
										</Form.Item>
									</Space.Compact>
								))}
							</Space>
						</Form.Item>
					)}
					{scopeAdvice(scopesValue) && (
						<Alert
							type="warning"
							showIcon
							style={{ marginBottom: 16 }}
							title="About this scope list"
							description={scopeAdvice(scopesValue)}
						/>
					)}
					<Form.Item
						name="tokenFormat"
						label="How its tokens are verified"
					>
						<Select options={TOKEN_FORMAT_OPTIONS} />
					</Form.Item>
					<Form.Item
						name="accessTokenTTL"
						label="Access token lifetime (seconds)"
					>
						<InputNumber
							min={30}
							max={86400}
							precision={0}
							style={{ width: '100%' }}
						/>
					</Form.Item>
					<ResourceSignInFields
						checkedBy={checkedByValue}
						every={everyValue}
					/>
					{/*
					 * FR-012: the check does not look a self-contained token's grant up on every request, so at the proxy
					 * a revoked one keeps working until it expires. Said here, where the format and lifetime are chosen.
					 */}
					{checkedByValue === 'proxy' ? (
						<Alert
							type={formatValue === 'jwt' ? 'warning' : 'info'}
							showIcon
							title={
								formatValue === 'jwt'
									? `A revoked token keeps working at your proxy for up to ${describeWindow(ttlValue)}`
									: 'Revocation is immediate'
							}
							description={
								formatValue === 'jwt'
									? 'Your proxy accepts a self-contained token until it expires, even after it is revoked. For an API your proxy checks, choose opaque tokens, or keep the lifetime short.'
									: 'The check looks each opaque token up in this project, so a revoked token is refused on the next request. Neither your proxy nor your API needs credentials for it.'
							}
						/>
					) : (
						<Alert
							type="info"
							showIcon
							title={
								formatValue === 'jwt'
									? `Revocation takes up to ${describeWindow(ttlValue)}`
									: 'Revocation is immediate'
							}
							description={
								formatValue === 'jwt'
									? 'A self-contained token is verified against this server’s published keys with no request back, so your resource needs no credentials of its own — and a revoked token stays valid until it expires. Shorten the lifetime to narrow that window.'
									: 'An opaque token is checked back with this server on every request, so revocation is immediate. Your resource needs credentials of its own and token introspection must be enabled.'
							}
						/>
					)}
				</Form>
			</Modal>
		</>
	);
}
