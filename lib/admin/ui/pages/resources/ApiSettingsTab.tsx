import { useEffect, useState } from 'react';
import {
	Alert,
	Button,
	Card,
	Checkbox,
	Flex,
	Form,
	Input,
	InputNumber,
	Radio,
	Select,
	Space,
	Typography
} from 'antd';
import { SCOPE_DESCRIPTION_MAX_LENGTH } from '../../../../resources/scopes.js';
import { request } from '../../frame/request.js';
import { useFeedback } from '../../frame/feedback.js';
import { useConfirm } from '../../frame/confirm.js';
import { Link, useLeaveGuard, useNavigate } from '../../frame/router.js';
import { bucketHref } from '../../frame/routes.js';
import { SaveBar } from '../../settings/SaveBar.js';
import type { Change } from '../../settings/model.js';
import {
	exchangeOptions,
	applicationName,
	type ExchangeCandidate
} from '../applications/exchange.js';
import { useCodeConsent, withConsent } from '../applications/codeConsent.js';
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
} from './resourceView.js';

interface SettingsForm {
	name: string;
	scopes: string;
	descriptions?: DescriptionsInput;
	tokenFormat: 'jwt' | 'opaque';
	// InputNumber answers null once the operator clears it.
	accessTokenTTL: number | null;
	checkedBy: CheckedBy;
	/* '' for none. */
	exchangedBy: string;
}

function formOf(api: ResourceView): SettingsForm {
	return {
		name: api.name,
		scopes: api.scopes.join(' '),
		descriptions: api.scopeDescriptions ?? {},
		tokenFormat: api.tokenFormat,
		accessTokenTTL: api.accessTokenTTL,
		checkedBy: api.checkedBy,
		exchangedBy: api.exchangedBy ?? ''
	};
}

/*
 * What describes an API and its tokens (specs/132 Settings), and its removal. Two things here are not decoration and
 * should survive any redesign.
 *
 * The scope-list warning, because a scope list is not a menu. A client given no scope guidance requests every scope
 * the resource advertises — the MCP specification says so, and says it is deliberate, since a general-purpose agent
 * cannot choose among names it does not understand. So a long list is a grant of the whole list to every client that
 * arrives, and an operator who has not been told that will write one.
 *
 * The revocation window, because the default token format is self-contained. A resource verifies such a token against
 * the published keys with no request back, which is what keeps setup to minutes — and the cost is that revocation
 * waits for expiry. Stating the resulting window next to the lifetime is the difference between a chosen trade-off and
 * a surprise.
 */
export function ApiSettingsTab({
	bucketId,
	api,
	writable,
	onChanged
}: {
	bucketId: string;
	api: ResourceView;
	writable: boolean;
	onChanged: () => void;
}) {
	const url = resourcesApi(bucketId, api.identifier);
	const [form] = Form.useForm<SettingsForm>();
	const feedback = useFeedback();
	const confirm = useConfirm();
	const navigate = useNavigate();
	const signInConsent = useCodeConsent('api');
	const [saved, setSaved] = useState<SettingsForm>(() => formOf(api));
	const [saving, setSaving] = useState(false);
	const [gone, setGone] = useState(false);
	const [applications, setApplications] = useState<ExchangeCandidate[]>([]);
	const values = Form.useWatch([], form) as SettingsForm | undefined;
	const scopesValue = values?.scopes ?? saved.scopes;
	const ttlValue = values?.accessTokenTTL ?? saved.accessTokenTTL ?? 900;
	const formatValue = values?.tokenFormat ?? saved.tokenFormat;
	const checkedByValue = values?.checkedBy ?? saved.checkedBy;

	useEffect(() => {
		let live = true;
		void request<ExchangeCandidate[]>(
			'GET',
			`/admin/api/projects/${encodeURIComponent(bucketId)}/clients`
		).then((result) => {
			if (live && result.ok) setApplications(result.data);
		});
		return () => {
			live = false;
		};
	}, [bucketId]);

	/* The form follows a save; it never re-reads the API while the administrator is editing. */
	useEffect(() => {
		form.setFieldsValue(saved);
	}, [form, saved]);

	const edited: SettingsForm = { ...saved, ...values };
	const shownScopes = (raw: string) => splitScopes(raw).join(' ');
	const describedNow = (form_: SettingsForm) =>
		describedScopes(splitScopes(form_.scopes), form_.descriptions);
	const changes: Change[] = [];
	const field = (
		key: string,
		label: string,
		from: unknown,
		to: unknown
	): void => {
		if (JSON.stringify(from) !== JSON.stringify(to)) {
			changes.push({ key, label, group: 'settings', from, to });
		}
	};
	field('name', 'Name', saved.name, edited.name);
	field(
		'scopes',
		'Scopes',
		shownScopes(saved.scopes),
		shownScopes(edited.scopes)
	);
	field(
		'scopeDescriptions',
		'What each scope lets an app do',
		describedNow(saved),
		describedNow(edited)
	);
	field('tokenFormat', 'Token format', saved.tokenFormat, edited.tokenFormat);
	field(
		'accessTokenTTL',
		'Access token lifetime',
		saved.accessTokenTTL,
		edited.accessTokenTTL
	);
	field('checkedBy', 'Who checks tokens', saved.checkedBy, edited.checkedBy);
	field(
		'exchangedBy',
		'Application that exchanges tokens',
		saved.exchangedBy
			? applicationName(saved.exchangedBy, applications)
			: 'none',
		edited.exchangedBy
			? applicationName(edited.exchangedBy, applications)
			: 'none'
	);
	useLeaveGuard(changes.length > 0, changes.length);

	async function save() {
		let valid: SettingsForm;
		try {
			valid = { ...saved, ...(await form.validateFields()) };
		} catch {
			return;
		}
		const scopes = splitScopes(valid.scopes);
		/*
		 * The identifier is absent deliberately, and the server refuses it if sent: it is the audience of every token
		 * already minted for this API, so replacing it is a removal and a fresh declaration rather than a rename.
		 */
		const body = {
			name: valid.name,
			scopes,
			// The whole map, so a description emptied here is removed rather than kept.
			scopeDescriptions: describedScopes(scopes, valid.descriptions),
			tokenFormat: valid.tokenFormat,
			accessTokenTTL: valid.accessTokenTTL ?? undefined,
			// Sent only when it changed, so the audit records a change of who checks only when there was one.
			...(valid.checkedBy !== saved.checkedBy
				? { checkedBy: valid.checkedBy }
				: {}),
			...(valid.exchangedBy !== saved.exchangedBy
				? { exchangedBy: valid.exchangedBy || null }
				: {})
		};
		setSaving(true);
		try {
			const result = await signInConsent(
				(consent) => request('PATCH', url, withConsent(body, consent)),
				valid.name
			);
			if (result === null) return;
			if (!result.ok) {
				if (result.status === 404) setGone(true);
				else feedback.failed(result, form);
				return;
			}
			feedback.done('Resource saved.');
			setSaved(valid);
			onChanged();
		} finally {
			setSaving(false);
		}
	}

	async function remove() {
		const clients = await request<
			{
				clientId: string;
				clientName?: string;
				registeredDynamically?: boolean;
			}[]
		>('GET', `/admin/api/projects/${encodeURIComponent(bucketId)}/clients`);
		const agreed = await confirm('resource.remove', {
			target: api.name,
			consequences: removalConsequences(clients.ok ? clients.data : null)
		});
		if (!agreed) return;
		const result = await request('DELETE', url);
		if (!result.ok && result.status !== 404) {
			feedback.failed(result);
			return;
		}
		feedback.done('Resource removed.');
		void navigate(bucketHref(bucketId, 'apis'));
	}

	if (gone) {
		return (
			<Alert
				type="warning"
				showIcon
				title="This API no longer exists."
				description={
					<Link href={bucketHref(bucketId, 'apis')}>Back to APIs</Link>
				}
			/>
		);
	}

	return (
		<Flex
			vertical
			gap={16}
		>
			<Card>
				<Form<SettingsForm>
					form={form}
					layout="vertical"
					initialValues={saved}
					disabled={!writable}
					scrollToFirstError
				>
					<Form.Item
						label="Resource identifier"
						extra="The canonical URI of your MCP server, exactly as its clients name it."
					>
						<Typography.Text
							code
							copyable={{ text: api.identifier }}
						>
							{api.identifier}
						</Typography.Text>
					</Form.Item>
					<Form.Item>
						<Checkbox
							checked={api.trailingSlashSignificant}
							disabled
						>
							The trailing slash is significant
						</Checkbox>
					</Form.Item>
					<Alert
						type="info"
						showIcon
						style={{ marginBottom: 16 }}
						title="The identifier cannot be changed"
						description="It is the audience of every token already issued for this resource. Replacing it means removing this declaration and making a new one."
					/>
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
					<Form.Item
						name="exchangedBy"
						label="Application that exchanges tokens for this API"
						extra="The application that serves this API, when it calls a connected service for the person who called it: it presents the access tokens this API receives to obtain that person's token there."
					>
						<Select
							showSearch={{ optionFilterProp: 'label' }}
							options={[
								{ value: '', label: 'None', disabled: false },
								...exchangeOptions(
									applications,
									saved.exchangedBy ? [saved.exchangedBy] : []
								)
							]}
						/>
					</Form.Item>
					{/*
					 * FR-012 (specs/123): the check does not look a self-contained token's grant up on every request, so at
					 * the proxy a revoked one keeps working until it expires. Said here, where the format and lifetime are
					 * chosen.
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
			</Card>

			<Card title="Remove this API">
				<Flex
					vertical
					gap={8}
					align="start"
				>
					<Typography.Text type="secondary">
						This server stops issuing tokens for it. Tokens already issued work
						until they expire.
					</Typography.Text>
					<Button
						danger
						disabled={!writable}
						onClick={() => void remove()}
					>
						Remove…
					</Button>
				</Flex>
			</Card>

			{writable && (
				<SaveBar
					changes={changes}
					saving={saving}
					onSave={() => void save()}
					onDiscard={() => {
						form.resetFields();
						form.setFieldsValue(saved);
					}}
				/>
			)}
		</Flex>
	);
}
