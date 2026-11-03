import { useEffect, useState } from 'react';
import {
	Alert,
	Button,
	Card,
	Drawer,
	Empty,
	Form,
	Input,
	Radio,
	Select,
	Table,
	Typography
} from 'antd';
import { DeleteOutlined, PlusOutlined } from '@ant-design/icons';
import { request } from '../frame/request.js';
import { useFeedback } from '../frame/feedback.js';
import { useConfirm } from '../frame/confirm.js';
import { Link } from '../frame/router.js';
import {
	applicationName,
	exchangeOptions,
	type ExchangeCandidate
} from './applications/exchange.js';

/*
 * A project's connected services (specs/117): the services its people may connect their accounts at, each with the
 * project's own registration at the provider. Every rule is the server's; the panel edits the record, shows the
 * callback address to register, and says what the server said when it refuses.
 */

interface ServiceView {
	id: string;
	kind: 'catalogue' | 'oidc' | 'oauth2';
	catalogueId?: string;
	issuer?: string;
	tenant?: string;
	authorizationEndpoint?: string;
	tokenEndpoint?: string;
	identity?:
		| { source: 'endpoint'; url: string; idPath: string; labelPath?: string }
		| { source: 'token'; idPath: string; labelPath?: string };
	revocationEndpoint?: string;
	clientId: string;
	scopes: string[];
	displayName: string;
	connectedAccounts: number;
	callbackUri: string;
	/* What an agent names as `audience` to obtain this service's tokens (specs/118). */
	identifier: string;
	/* The applications allowed to obtain a person's tokens here, once that person allows them. */
	applications: string[];
	/* The sign-in provider whose sign-ins also connect accounts here, and those that could be (specs/120). */
	signInProvider?: { id: string; displayName: string };
	linkableSignInProviders: { id: string; displayName: string }[];
}

interface CatalogueEntry {
	catalogueId: string;
	displayName: string;
	requiredValues: {
		name: string;
		label: string;
		secret: boolean;
		hint: string;
	}[];
	defaultScopes: string[];
	consoleUrl: string;
	steps: string[];
}

interface ServiceForm {
	kind: 'catalogue' | 'oidc' | 'oauth2';
	catalogueId?: string;
	tenant?: string;
	issuer?: string;
	authorizationEndpoint?: string;
	tokenEndpoint?: string;
	identitySource?: 'endpoint' | 'token';
	identityUrl?: string;
	idPath?: string;
	labelPath?: string;
	revocationEndpoint?: string;
	clientId: string;
	clientSecret?: string;
	scopes: string[];
	displayName?: string;
	applications: string[];
	signInProviderId?: string;
}

const MASK = '********';

function trimmed(value: string | undefined): string | undefined {
	const text = value?.trim();
	return text ? text : undefined;
}

function identityOf(form: ServiceForm) {
	const idPath = trimmed(form.idPath) ?? '';
	const labelPath = trimmed(form.labelPath);
	return form.identitySource === 'endpoint'
		? {
				source: 'endpoint' as const,
				url: trimmed(form.identityUrl) ?? '',
				idPath,
				...(labelPath ? { labelPath } : {})
			}
		: { source: 'token' as const, idPath, ...(labelPath ? { labelPath } : {}) };
}

function createBody(form: ServiceForm) {
	const common = {
		clientId: form.clientId.trim(),
		clientSecret: form.clientSecret ?? '',
		scopes: form.scopes,
		...(form.applications.length ? { applications: form.applications } : {})
	};
	if (form.kind === 'catalogue') {
		return {
			kind: 'catalogue',
			catalogueId: form.catalogueId,
			...(trimmed(form.tenant) ? { tenant: trimmed(form.tenant) } : {}),
			...common,
			...(trimmed(form.displayName)
				? { displayName: trimmed(form.displayName) }
				: {})
		};
	}
	if (form.kind === 'oidc') {
		return {
			kind: 'oidc',
			issuer: trimmed(form.issuer),
			...common,
			displayName: trimmed(form.displayName) ?? ''
		};
	}
	return {
		kind: 'oauth2',
		authorizationEndpoint: trimmed(form.authorizationEndpoint),
		tokenEndpoint: trimmed(form.tokenEndpoint),
		identity: identityOf(form),
		...(trimmed(form.revocationEndpoint)
			? { revocationEndpoint: trimmed(form.revocationEndpoint) }
			: {}),
		...common,
		displayName: trimmed(form.displayName) ?? ''
	};
}

function updateBody(form: ServiceForm, service: ServiceView) {
	return {
		scopes: form.scopes,
		applications: form.applications,
		signInProviderId: form.signInProviderId ?? null,
		...(trimmed(form.displayName)
			? { displayName: trimmed(form.displayName) }
			: {}),
		// The mask, or nothing, leaves the secret as it is.
		...(form.clientSecret && form.clientSecret !== MASK
			? { clientSecret: form.clientSecret }
			: {}),
		...(service.kind === 'oauth2'
			? {
					authorizationEndpoint: trimmed(form.authorizationEndpoint),
					tokenEndpoint: trimmed(form.tokenEndpoint),
					identity: identityOf(form),
					...(trimmed(form.revocationEndpoint)
						? { revocationEndpoint: trimmed(form.revocationEndpoint) }
						: {})
				}
			: {})
	};
}

function formOf(service: ServiceView): ServiceForm {
	return {
		kind: service.kind,
		catalogueId: service.catalogueId,
		tenant: service.tenant,
		issuer: service.issuer,
		authorizationEndpoint: service.authorizationEndpoint,
		tokenEndpoint: service.tokenEndpoint,
		identitySource: service.identity?.source ?? 'token',
		identityUrl:
			service.identity?.source === 'endpoint'
				? service.identity.url
				: undefined,
		idPath: service.identity?.idPath,
		labelPath: service.identity?.labelPath,
		revocationEndpoint: service.revocationEndpoint,
		clientId: service.clientId,
		clientSecret: MASK,
		scopes: service.scopes,
		displayName: service.displayName,
		applications: service.applications,
		...(service.signInProvider
			? { signInProviderId: service.signInProvider.id }
			: {})
	};
}

/* The linked provider first, so it stays selectable even if a later edit made it unmatchable. */
function signInOptions(service: ServiceView) {
	const listed = service.linkableSignInProviders;
	const current = service.signInProvider;
	const all =
		current && !listed.some((item) => item.id === current.id)
			? [current, ...listed]
			: listed;
	return all.map((item) => ({ value: item.id, label: item.displayName }));
}

function providerOf(service: ServiceView): string {
	if (service.kind === 'catalogue') return service.catalogueId ?? 'catalogue';
	if (service.kind === 'oidc') return service.issuer ?? 'OpenID Connect';
	return service.tokenEndpoint
		? new URL(service.tokenEndpoint).host
		: 'OAuth 2.0';
}

export function ConnectedServicesPanel({
	bucketId,
	canEdit
}: {
	bucketId: string;
	canEdit: boolean;
}) {
	const projectBase = `/admin/api/projects/${encodeURIComponent(bucketId)}`;
	const base = `${projectBase}/connected-services`;
	const feedback = useFeedback();
	const confirm = useConfirm();
	const [services, setServices] = useState<ServiceView[] | null>(null);
	const [callbackUri, setCallbackUri] = useState('');
	const [catalogue, setCatalogue] = useState<CatalogueEntry[]>([]);
	const [applications, setApplications] = useState<ExchangeCandidate[]>([]);
	const [editing, setEditing] = useState<ServiceView | 'new' | null>(null);
	/*
	 * Null while unknown, and for anyone but a super administrator, who alone may read the keyring status: a
	 * tenant then meets the server's own refusal when there is no keyring, which says the same.
	 */
	const [keyringInUse, setKeyringInUse] = useState<boolean | null>(null);

	const [version, setVersion] = useState(0);
	const reload = () => setVersion((current) => current + 1);

	useEffect(() => {
		let live = true;
		void Promise.all([
			request<{ services: ServiceView[]; callbackUri: string }>('GET', base),
			request<{ entries: CatalogueEntry[] }>('GET', `${base}/catalogue`),
			request<{ state: string }>('GET', '/admin/api/keyring'),
			request<ExchangeCandidate[]>('GET', `${projectBase}/clients`)
		]).then(([list, entries, keyring, clients]) => {
			if (!live) return;
			if (clients.ok) setApplications(clients.data);
			if (keyring.ok) setKeyringInUse(keyring.data.state === 'in-use');
			if (list.ok) {
				setServices(list.data.services);
				setCallbackUri(list.data.callbackUri);
			} else {
				feedback.failed(list);
				setServices([]);
			}
			if (entries.ok) setCatalogue(entries.data.entries);
		});
		return () => {
			live = false;
		};
	}, [base, projectBase, feedback, version]);

	async function remove(service: ServiceView) {
		const agreed = await confirm('connectedService.delete', {
			target: service.displayName,
			consequences: [
				service.connectedAccounts === 1
					? '1 connected account will be disconnected, and the provider asked to revoke it.'
					: `${String(service.connectedAccounts)} connected accounts will be disconnected, and the provider asked to revoke each.`,
				'People must connect again to a new service.'
			]
		});
		if (!agreed) return;
		const result = await request(
			'DELETE',
			`${base}/${encodeURIComponent(service.id)}`
		);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done(`${service.displayName} deleted.`);
		reload();
	}

	return (
		<Card
			title="Connected services"
			extra={
				canEdit &&
				keyringInUse !== false && (
					<Button
						type="primary"
						icon={<PlusOutlined />}
						onClick={() => setEditing('new')}
					>
						Add
					</Button>
				)
			}
		>
			{keyringInUse === false && (
				<Alert
					type="warning"
					showIcon
					style={{ marginBottom: 16 }}
					title="Stored secrets are not encrypted on this instance"
					description={
						<>
							A connected service keeps people&apos;s tokens, which are never
							stored unencrypted. Add a keyring on the{' '}
							<Link href="/admin/keys">Keys</Link> page first.
						</>
					}
				/>
			)}
			{callbackUri && (
				<Typography.Paragraph type="secondary">
					Register this callback address at each provider:{' '}
					<Typography.Text
						code
						copyable
					>
						{callbackUri}
					</Typography.Text>
				</Typography.Paragraph>
			)}
			{services && services.length === 0 ? (
				<Empty description="Let the people of this project connect their accounts at other services, such as Google, GitHub, Slack or Microsoft, so that applications you allow can act there for them." />
			) : (
				<Table<ServiceView>
					rowKey="id"
					loading={services === null}
					dataSource={services ?? []}
					pagination={false}
					columns={[
						{
							title: 'Name',
							dataIndex: 'displayName',
							render: (name: string, service) =>
								canEdit ? (
									<Typography.Link onClick={() => setEditing(service)}>
										{name}
									</Typography.Link>
								) : (
									name
								)
						},
						{ title: 'Provider', render: (_, service) => providerOf(service) },
						{
							title: 'Identifier for agents',
							render: (_, service) => (
								<Typography.Text
									code
									copyable
								>
									{service.identifier}
								</Typography.Text>
							)
						},
						{
							title: 'Scopes',
							render: (_, service) =>
								service.scopes.length ? service.scopes.join(' ') : 'None'
						},
						{
							title: 'Applications',
							render: (_, service) =>
								service.applications.length
									? service.applications
											.map((clientId) =>
												applicationName(clientId, applications)
											)
											.join(', ')
									: 'None'
						},
						{ title: 'Connected accounts', dataIndex: 'connectedAccounts' },
						...(canEdit
							? [
									{
										title: '',
										key: 'actions',
										render: (_: unknown, service: ServiceView) => (
											<Button
												danger
												size="small"
												icon={<DeleteOutlined />}
												aria-label={`Delete ${service.displayName}`}
												onClick={() => void remove(service)}
											/>
										)
									}
								]
							: [])
					]}
				/>
			)}
			{editing !== null && (
				<ServiceEditor
					base={base}
					service={editing === 'new' ? null : editing}
					catalogue={catalogue}
					applications={applications}
					callbackUri={callbackUri}
					onClose={() => setEditing(null)}
					onSaved={() => {
						setEditing(null);
						reload();
					}}
				/>
			)}
		</Card>
	);
}

function ServiceEditor({
	base,
	service,
	catalogue,
	applications,
	callbackUri,
	onClose,
	onSaved
}: {
	base: string;
	service: ServiceView | null;
	catalogue: CatalogueEntry[];
	applications: ExchangeCandidate[];
	callbackUri: string;
	onClose: () => void;
	onSaved: () => void;
}) {
	const feedback = useFeedback();
	const confirm = useConfirm();
	const [form] = Form.useForm<ServiceForm>();
	const [saving, setSaving] = useState(false);
	const [refusal, setRefusal] = useState<string | null>(null);
	const editing = service !== null;
	/*
	 * The form's initial values set both, so the first render, before the form has mounted and the watch answers,
	 * shows only the fields every kind shares.
	 */
	const kind = Form.useWatch('kind', form);
	const catalogueId = Form.useWatch('catalogueId', form);
	const identitySource = Form.useWatch('identitySource', form);
	const entry = catalogue.find((item) => item.catalogueId === catalogueId);
	const needsTenant =
		entry?.requiredValues.some((value) => value.name === 'tenant') ?? false;

	async function save(values: ServiceForm) {
		await confirm(
			editing ? 'connectedService.edit' : 'connectedService.create',
			{
				target: values.displayName ?? entry?.displayName ?? ''
			}
		);
		setSaving(true);
		try {
			const result = await request(
				editing ? 'PATCH' : 'POST',
				editing ? `${base}/${encodeURIComponent(service.id)}` : base,
				editing ? updateBody(values, service) : createBody(values)
			);
			if (!result.ok) {
				if (result.status >= 500) feedback.failed(result);
				else setRefusal(result.error.message);
				return;
			}
			feedback.done(
				`${values.displayName ?? entry?.displayName ?? 'Service'} saved.`
			);
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
				editing ? `Edit ${service.displayName}` : 'Add a connected service'
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
			{editing && (
				<Typography.Paragraph>
					Identifier for agents:{' '}
					<Typography.Text
						code
						copyable
					>
						{service.identifier}
					</Typography.Text>
					<br />
					<Typography.Text type="secondary">
						An application names it as the audience when it asks for a
						person&apos;s token at this service.
					</Typography.Text>
				</Typography.Paragraph>
			)}
			{entry && !editing && (
				<Alert
					type="info"
					showIcon
					style={{ marginBottom: 16 }}
					title={`Register an application at ${entry.displayName}`}
					description={
						<>
							<ol style={{ margin: 0, paddingLeft: 20 }}>
								{entry.steps.map((step) => (
									<li key={step}>{step}</li>
								))}
							</ol>
							<Typography.Paragraph style={{ margin: '8px 0 0' }}>
								<Typography.Link
									href={entry.consoleUrl}
									target="_blank"
									rel="noreferrer"
								>
									Open {entry.displayName}
								</Typography.Link>{' '}
								· Callback:{' '}
								<Typography.Text
									code
									copyable
								>
									{callbackUri}
								</Typography.Text>
							</Typography.Paragraph>
						</>
					}
				/>
			)}
			<Form<ServiceForm>
				form={form}
				layout="vertical"
				initialValues={
					service
						? formOf(service)
						: {
								kind: 'catalogue',
								catalogueId: 'github',
								scopes: ['read:user'],
								identitySource: 'token',
								applications: []
							}
				}
				onFinish={(values) => void save(values)}
				onValuesChange={(changed: Partial<ServiceForm>) => {
					setRefusal(null);
					if (changed.catalogueId) {
						const picked = catalogue.find(
							(item) => item.catalogueId === changed.catalogueId
						);
						if (picked) form.setFieldValue('scopes', picked.defaultScopes);
					}
				}}
			>
				<Form.Item
					name="kind"
					label="Provider"
				>
					<Radio.Group disabled={editing}>
						<Radio.Button value="catalogue">By name</Radio.Button>
						<Radio.Button value="oidc">OpenID Connect</Radio.Button>
						<Radio.Button value="oauth2">OAuth 2.0</Radio.Button>
					</Radio.Group>
				</Form.Item>
				{kind === 'catalogue' && (
					<Form.Item
						name="catalogueId"
						label="Service"
						rules={[{ required: true }]}
					>
						<Select
							disabled={editing}
							options={catalogue.map((item) => ({
								value: item.catalogueId,
								label: item.displayName
							}))}
						/>
					</Form.Item>
				)}
				{kind === 'catalogue' && needsTenant && (
					<Form.Item
						name="tenant"
						label="Directory"
						extra='"common" for work and personal accounts, "organizations", "consumers", or a directory ID.'
						rules={[{ required: true }]}
					>
						<Input disabled={editing} />
					</Form.Item>
				)}
				{kind === 'oidc' && (
					<Form.Item
						name="issuer"
						label="Issuer"
						rules={[{ required: true }]}
					>
						<Input
							disabled={editing}
							placeholder="https://accounts.example.com"
						/>
					</Form.Item>
				)}
				{kind === 'oauth2' && (
					<>
						<Form.Item
							name="authorizationEndpoint"
							label="Authorization endpoint"
							rules={[{ required: true }]}
						>
							<Input placeholder="https://example.com/oauth/authorize" />
						</Form.Item>
						<Form.Item
							name="tokenEndpoint"
							label="Token endpoint"
							rules={[{ required: true }]}
						>
							<Input placeholder="https://example.com/oauth/token" />
						</Form.Item>
						<Form.Item
							name="identitySource"
							label="Who the account is"
							extra="Required: without it, a second account cannot be told from the first."
						>
							<Radio.Group>
								<Radio.Button value="token">From the token answer</Radio.Button>
								<Radio.Button value="endpoint">From an endpoint</Radio.Button>
							</Radio.Group>
						</Form.Item>
						{identitySource === 'endpoint' && (
							<Form.Item
								name="identityUrl"
								label="Identity endpoint"
								rules={[{ required: true }]}
							>
								<Input placeholder="https://example.com/api/me" />
							</Form.Item>
						)}
						<Form.Item
							name="idPath"
							label="Path to the account id"
							extra="Dotted, for example user.id; a|b takes the first present."
							rules={[{ required: true }]}
						>
							<Input />
						</Form.Item>
						<Form.Item
							name="labelPath"
							label="Path to a name for people (optional)"
						>
							<Input placeholder="user.name" />
						</Form.Item>
						<Form.Item
							name="revocationEndpoint"
							label="Revocation endpoint (optional)"
						>
							<Input placeholder="https://example.com/oauth/revoke" />
						</Form.Item>
					</>
				)}
				<Form.Item
					name="clientId"
					label="Client ID"
					rules={[{ required: true }]}
				>
					<Input disabled={editing} />
				</Form.Item>
				<Form.Item
					name="clientSecret"
					label="Client secret"
					extra="Stored encrypted; never shown again."
					rules={editing ? [] : [{ required: true }]}
				>
					<Input.Password autoComplete="new-password" />
				</Form.Item>
				<Form.Item
					name="scopes"
					label="Scopes"
					extra="What applications will be able to ask for. People who connected before keep what they granted."
				>
					<Select
						mode="tags"
						tokenSeparators={[' ', ',']}
					/>
				</Form.Item>
				<Form.Item
					name="displayName"
					label="Name people see"
					rules={kind === 'catalogue' ? [] : [{ required: true }]}
				>
					<Input placeholder={entry?.displayName} />
				</Form.Item>
				<Form.Item
					name="applications"
					label="Applications that may obtain tokens"
					extra="An application listed here can obtain a person's token at this service only after that person allows it. Removing one stops its next request; tokens it already received stay valid at the provider until they expire."
				>
					<Select
						mode="multiple"
						allowClear
						showSearch={{ optionFilterProp: 'label' }}
						placeholder="None"
						options={exchangeOptions(applications, service?.applications)}
					/>
				</Form.Item>
				{service && (
					<Form.Item
						name="signInProviderId"
						label="Keep tokens when people sign in with"
						extra="A sign-in through this provider also connects the person's account here, so they need not connect it separately. Only a sign-in provider at the same provider with the same client ID can be chosen. If an organisation refuses these extra scopes, the sign-in is retried once without them; an organisation that blocks them on the provider's own page cannot be retried, so unlink for such organisations."
					>
						<Select
							allowClear
							placeholder="None"
							options={signInOptions(service)}
						/>
					</Form.Item>
				)}
			</Form>
		</Drawer>
	);
}
