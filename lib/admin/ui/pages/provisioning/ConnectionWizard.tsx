import { useEffect, useState, type ReactNode } from 'react';
import {
	Alert,
	App,
	Button,
	Descriptions,
	Drawer,
	Flex,
	Form,
	Input,
	InputNumber,
	Radio,
	Select,
	Steps,
	Tag,
	Typography
} from 'antd';
import { CheckCircleOutlined, LoadingOutlined } from '@ant-design/icons';
import type { FederationProvider } from '../../../../federation/types.js';
import { request } from '../../frame/request.js';
import { useFeedback } from '../../frame/feedback.js';
import { useNavigate } from '../../frame/router.js';
import { connectionHref } from '../../frame/routes.js';
import { SecretReveal } from '../../frame/SecretReveal.js';
import {
	federationApi,
	type ProviderDetail
} from '../providers/providerTypes.js';
import {
	CREDENTIAL_KINDS,
	Copyable,
	DIRECTORY_CHOICES,
	MAX_WINDOW_SECONDS,
	MIN_WINDOW_SECONDS,
	WINDOW_UNITS,
	connectionsApi,
	directoriesApi,
	parseJwks,
	setupDetails,
	type ConnectionView,
	type CredentialKind,
	type DirectoryGuidance,
	type DirectoryId
} from './connectionShared.js';

/*
 * Creating a provisioning connection, as five steps in a side panel (specs/084 US4).
 *
 * The connection is created at the end of step three, once the three decisions that shape it are made — which
 * provider its people sign in with, how a sign-in finds the account the directory created, and what happens
 * when the directory removes many people at once. That last one has no default: holding protects against a
 * wrong rule in the directory, applying at once is what the directory expects, and only the operator knows
 * which matters more for this customer.
 *
 * The credential is shown in the panel that produced it, never in a window over it, and the panel does not
 * move on until the operator says it is stored. The last step watches for the directory's first request, so
 * the operator learns that the setup worked before they leave rather than when a person is missing.
 */

const POLL_MS = 10_000;
const POLL_LIMIT = 60; // ten minutes

interface Values {
	directory?: DirectoryId;
	displayName?: string;
	providerId?: string;
	matching?: 'recommended' | 'custom';
	claim?: string;
	attribute?: 'externalId' | 'userName';
	emailTrust?: 'trusted' | 'untrusted';
	safeguard?: 'hold' | 'immediate';
	count?: number;
	windowAmount?: number;
	windowUnit?: number;
	kind?: CredentialKind;
	keySource?: 'jwks' | 'jwksUri';
	jwksText?: string;
	jwksUri?: string;
	signingAlg?: string;
	lifetimeDays?: 90 | 365;
}

const STEP_FIELDS: (keyof Values)[][] = [
	['directory', 'displayName', 'providerId'],
	['matching', 'claim', 'attribute', 'emailTrust'],
	['safeguard', 'count', 'windowAmount', 'windowUnit']
];

export function ConnectionWizard({
	bucketId,
	bucketName,
	providers,
	onClose
}: {
	bucketId: string;
	bucketName: string;
	/* The bucket's providers without a connection — each holds at most one. */
	providers: FederationProvider[];
	onClose: () => void;
}) {
	const { modal } = App.useApp();
	const feedback = useFeedback();
	const navigate = useNavigate();
	const [form] = Form.useForm<Values>();
	const [step, setStep] = useState(0);
	const [busy, setBusy] = useState(false);
	const [refusal, setRefusal] = useState<string | null>(null);
	const [recommended, setRecommended] = useState<
		ProviderDetail['recommendedCorrelation'] | null
	>(null);
	const [created, setCreated] = useState<ConnectionView | null>(null);
	const [revealed, setRevealed] = useState<{
		noun: string;
		value: string;
	} | null>(null);
	const [stored, setStored] = useState(false);
	const [keyIssued, setKeyIssued] = useState(false);
	const [firstRequest, setFirstRequest] = useState<string | null>(null);
	const [gaveUp, setGaveUp] = useState(false);
	const [directories, setDirectories] = useState<DirectoryGuidance[]>([]);

	const providerId = Form.useWatch('providerId', form);
	const matching = Form.useWatch('matching', form);
	const safeguard = Form.useWatch('safeguard', form);
	const kind = Form.useWatch('kind', form);
	const keySource = Form.useWatch('keySource', form);
	// Read on later steps too, after step one's field has unmounted, so the watch keeps its value.
	const directory = Form.useWatch('directory', { form, preserve: true });
	const provider = providers.find((p) => p.id === providerId) ?? null;
	const guidance = directories.find((d) => d.id === directory);

	// The directory's own words and advice are the server's (specs/088), read once for this bucket.
	useEffect(() => {
		void request<{ directories: DirectoryGuidance[] }>(
			'GET',
			directoriesApi(bucketId)
		).then((r) => {
			if (r.ok) setDirectories(r.data.directories);
		});
	}, [bucketId]);

	// The recommended matching rule is the server's, read for the chosen provider.
	useEffect(() => {
		if (!providerId) return;
		let live = true;
		void request<ProviderDetail>(
			'GET',
			federationApi(bucketId, providerId)
		).then((r) => {
			if (!live) return;
			setRecommended(r.ok ? r.data.recommendedCorrelation : null);
			if (r.ok && !form.isFieldTouched('directory')) {
				form.setFieldsValue({
					directory: r.data.recognised === 'microsoft' ? 'entra' : 'generic'
				});
			}
		});
		return () => {
			live = false;
		};
	}, [bucketId, providerId, form]);

	// Watch for the directory's first request while the last step is open: every ten seconds, for ten minutes.
	useEffect(() => {
		if (step !== 4 || !created || firstRequest !== null) return;
		let ticks = 0;
		const timer = setInterval(() => {
			ticks += 1;
			void request<ConnectionView>(
				'GET',
				connectionsApi(bucketId, created.id)
			).then((r) => {
				if (r.ok && r.data.lastUsedAt) {
					setFirstRequest(r.data.lastUsedAt);
				}
			});
			if (ticks >= POLL_LIMIT) {
				clearInterval(timer);
				setGaveUp(true);
			}
		}, POLL_MS);
		return () => clearInterval(timer);
	}, [step, created, firstRequest, bucketId]);

	async function next() {
		const fields = STEP_FIELDS.at(step);
		if (fields) {
			try {
				await form.validateFields(fields);
			} catch {
				return;
			}
		}
		setRefusal(null);
		if (step === 2) {
			await create();
			return;
		}
		setStep((s) => s + 1);
	}

	async function create() {
		const v = form.getFieldsValue(true) as Values;
		setBusy(true);
		try {
			const result = await request<ConnectionView>(
				'POST',
				connectionsApi(bucketId),
				{
					displayName: v.displayName,
					providerId: v.providerId,
					directory: v.directory,
					emailTrust: v.emailTrust,
					...(v.matching === 'custom' && v.claim && v.attribute
						? { correlation: { claim: v.claim.trim(), attribute: v.attribute } }
						: {}),
					threshold:
						v.safeguard === 'hold'
							? {
									count: v.count ?? 50,
									windowSeconds: (v.windowAmount ?? 1) * (v.windowUnit ?? 3600)
								}
							: null
				}
			);
			if (!result.ok) {
				if (result.status >= 500 || result.error.error_reference) {
					feedback.failed(result);
				} else {
					setRefusal(result.error.message);
					const field = result.error.field;
					setStep(
						field === 'threshold'
							? 2
							: field === 'correlation' || field === 'emailTrust'
								? 1
								: 0
					);
				}
				return;
			}
			setCreated(result.data);
			feedback.done(
				`Provisioning connection ${result.data.displayName} created; ${result.data.providerId} now signs in existing accounts only.`
			);
			const offered = result.data.availableCredentialKinds;
			const preferred = [
				guidance?.recommendedCredential,
				guidance?.fallbackCredential,
				...CREDENTIAL_KINDS.map((k) => k.kind)
			].find((k) => k !== undefined && offered.includes(k));
			form.setFieldsValue({
				kind: preferred,
				keySource: 'jwks',
				lifetimeDays: 365
			});
			setStep(3);
		} finally {
			setBusy(false);
		}
	}

	async function issue() {
		if (!created || !kind) return;
		let body: Record<string, unknown> =
			kind === 'static_token'
				? {
						kind,
						lifetimeDays:
							(form.getFieldsValue(true) as Values).lifetimeDays ?? 365
					}
				: { kind };
		if (kind === 'key') {
			try {
				await form.validateFields(['jwksText', 'jwksUri']);
			} catch {
				return;
			}
			const v = form.getFieldsValue(true) as Values;
			const signingAlg = v.signingAlg?.trim();
			body = {
				kind,
				...(v.keySource === 'jwksUri'
					? { jwksUri: v.jwksUri?.trim() }
					: { jwks: parseJwks(v.jwksText) }),
				...(signingAlg ? { signingAlg } : {})
			};
		}
		setBusy(true);
		try {
			const result = await request<{
				connection: ConnectionView;
				secret?: string;
				token?: string;
			}>('POST', `${connectionsApi(bucketId, created.id)}/credentials`, body);
			if (!result.ok) {
				if (result.status >= 500 || result.error.error_reference) {
					feedback.failed(result);
				} else {
					setRefusal(result.error.message);
				}
				return;
			}
			setRefusal(null);
			setCreated(result.data.connection);
			if (result.data.secret) {
				setRevealed({ noun: 'client secret', value: result.data.secret });
			} else if (result.data.token) {
				setRevealed({ noun: 'static token', value: result.data.token });
			} else {
				setKeyIssued(true);
			}
		} finally {
			setBusy(false);
		}
	}

	function finish() {
		onClose();
		if (created) void navigate(connectionHref(bucketId, created.id));
	}

	/*
	 * Closing while a revealed secret is not yet stored loses it for good, so that one close asks, defaulting
	 * to going back. Closing after creation lands on the connection's page, where the rest can be done later.
	 */
	function close() {
		if (revealed && !stored) {
			modal.confirm({
				title: 'Close without storing the credential?',
				content:
					'It is shown only once. Closing now means issuing a new one later.',
				okText: 'Close anyway',
				okButtonProps: { danger: true },
				cancelText: 'Go back',
				focusable: { autoFocusButton: 'cancel' },
				onOk: finish
			});
			return;
		}
		if (created) finish();
		else onClose();
	}

	async function copySetup() {
		if (!created) return;
		try {
			await navigator.clipboard.writeText(setupDetails(created, guidance));
			feedback.done('Setup details copied, without the secret.');
		} catch {
			feedback.refused({
				error: 'clipboard',
				message:
					'The details could not be copied. Select them and copy them by hand.'
			});
		}
	}

	const available: CredentialKind[] = created?.availableCredentialKinds ?? [
		'key',
		'secret',
		'static_token'
	];
	const credentialDone = revealed ? stored : keyIssued;

	const refusalAlert = refusal && (
		<Alert
			type="error"
			showIcon
			style={{ marginBottom: 16 }}
			title="Not done"
			description={refusal}
		/>
	);

	const steps: { title: string; content: ReactNode }[] = [
		{
			title: 'Directory',
			content: (
				<>
					<Form.Item
						name="directory"
						label="Which directory provisions this bucket?"
						extra="Decides the field names and advice shown from here on; nothing else."
						initialValue="generic"
						rules={[{ required: true }]}
					>
						<Radio.Group
							optionType="button"
							options={DIRECTORY_CHOICES}
						/>
					</Form.Item>
					<Form.Item
						name="displayName"
						label="Name"
						rules={[{ required: true, max: 100 }]}
					>
						<Input
							placeholder={`${guidance && guidance.id !== 'generic' ? guidance.displayName : 'Directory'} provisioning for Acme`}
						/>
					</Form.Item>
					<Form.Item
						name="providerId"
						label="Sign-in provider"
						extra="The provider the directory's people sign in with."
						rules={[{ required: true, message: 'Choose the provider.' }]}
					>
						<Select
							options={providers.map((p) => ({
								label: `${p.displayName} (${p.id})`,
								value: p.id
							}))}
						/>
					</Form.Item>
					{provider && (
						<Alert
							type="warning"
							showIcon
							title={`Creating this connection limits ${provider.displayName} to accounts the directory has created`}
							description="It stops creating accounts at first sign-in, so a person is never created twice."
						/>
					)}
				</>
			)
		},
		{
			title: 'Matching & trust',
			content: (
				<>
					<Form.Item
						name="matching"
						label="How a sign-in finds the account the directory created"
						initialValue="recommended"
					>
						<Radio.Group>
							<Flex
								vertical
								gap={8}
							>
								<Radio value="recommended">
									Recommended for this provider
									{recommended && (
										<Typography.Text type="secondary">
											{' '}
											—{' '}
											<Typography.Text code>
												{recommended.claim}
											</Typography.Text>{' '}
											↔{' '}
											<Typography.Text code>
												{recommended.attribute}
											</Typography.Text>
										</Typography.Text>
									)}
								</Radio>
								<Radio value="custom">Custom</Radio>
							</Flex>
						</Radio.Group>
					</Form.Item>
					{matching === 'custom' && (
						<Flex gap={12}>
							<Form.Item
								name="claim"
								label="ID token claim"
								style={{ flex: 1 }}
								rules={[
									{ required: true },
									{
										pattern: /^[A-Za-z0-9_.:-]{1,64}$/,
										message: 'letters, digits and _ . : - only'
									}
								]}
							>
								<Input autoComplete="off" />
							</Form.Item>
							<Form.Item
								name="attribute"
								label="SCIM attribute"
								style={{ width: 180 }}
								rules={[{ required: true }]}
							>
								<Select
									options={[
										{ label: 'externalId', value: 'externalId' },
										{ label: 'userName', value: 'userName' }
									]}
								/>
							</Form.Item>
						</Flex>
					)}
					<Form.Item
						name="emailTrust"
						label="Email addresses from the directory"
						initialValue="untrusted"
					>
						<Radio.Group>
							<Flex
								vertical
								gap={8}
							>
								<Radio value="untrusted">
									Treat as unverified — people confirm their address themselves
								</Radio>
								<Radio value="trusted">
									Treat as verified — the directory vouches for them
								</Radio>
							</Flex>
						</Radio.Group>
					</Form.Item>
				</>
			)
		},
		{
			title: 'Safeguard',
			content: (
				<>
					<Form.Item
						name="safeguard"
						label="The directory removes many people at once. What happens?"
						rules={[{ required: true, message: 'Choose what happens.' }]}
					>
						<Radio.Group>
							<Flex
								vertical
								gap={12}
							>
								<Radio value="hold">
									Hold the connection, and email the owners, if it removes more
									than a limit within a window
								</Radio>
								<Radio value="immediate">Apply every removal immediately</Radio>
							</Flex>
						</Radio.Group>
					</Form.Item>
					{safeguard === 'hold' && (
						<>
							<Flex
								gap={8}
								align="start"
								wrap
							>
								<Form.Item
									name="count"
									label="At most"
									initialValue={50}
									rules={[{ required: true }]}
								>
									<InputNumber
										min={1}
										max={100000}
										precision={0}
										style={{ width: 110 }}
									/>
								</Form.Item>
								<Form.Item
									name="windowAmount"
									label="within"
									initialValue={1}
									dependencies={['windowUnit']}
									rules={[
										{ required: true },
										({ getFieldValue }) => ({
											validator: async (_rule, amount: number | undefined) => {
												const seconds =
													(amount ?? 0) * Number(getFieldValue('windowUnit'));
												if (
													seconds < MIN_WINDOW_SECONDS ||
													seconds > MAX_WINDOW_SECONDS
												) {
													throw new Error('between 5 minutes and 7 days');
												}
											}
										})
									]}
								>
									<InputNumber
										min={1}
										precision={0}
										style={{ width: 80 }}
									/>
								</Form.Item>
								<Form.Item
									name="windowUnit"
									label=" "
									initialValue={3600}
								>
									<Select
										options={WINDOW_UNITS}
										style={{ width: 110 }}
									/>
								</Form.Item>
							</Flex>
							<Typography.Paragraph type="secondary">
								A common choice is about 5% of the people it will manage, per
								hour. While held, the people it tries to remove keep their
								access until someone releases the hold.
							</Typography.Paragraph>
						</>
					)}
					{safeguard === 'immediate' && (
						<Typography.Paragraph type="secondary">
							What the directory expects: a person it removes loses access at
							once. A wrong rule in the directory can remove everyone before
							anyone notices.
						</Typography.Paragraph>
					)}
					<Typography.Text type="secondary">
						Will be created in {bucketName}.
					</Typography.Text>
				</>
			)
		},
		{
			title: 'Credential',
			content: (
				<>
					{revealed ? (
						<SecretReveal
							secret={revealed.value}
							noun={revealed.noun}
							acknowledged={stored}
							onAcknowledged={setStored}
							acknowledgement="I've put it into the directory"
						/>
					) : keyIssued ? (
						<Alert
							type="success"
							showIcon
							title="Key credential issued"
							description="The directory signs its requests with the private half; nothing secret is stored here."
						/>
					) : (
						<>
							<Form.Item
								name="kind"
								label="How the directory authenticates"
							>
								<Radio.Group>
									<Flex
										vertical
										gap={8}
									>
										{CREDENTIAL_KINDS.map((k) => (
											<Radio
												key={k.kind}
												value={k.kind}
												disabled={!available.includes(k.kind)}
											>
												{k.label}{' '}
												{guidance?.recommendedCredential === k.kind && (
													<Tag color="blue">
														Recommended for {guidance.displayName}
													</Tag>
												)}
												{guidance?.fallbackCredential === k.kind && (
													<Tag>
														If {guidance.displayName} offers no OAuth option
													</Tag>
												)}
												<Typography.Text type="secondary">
													{available.includes(k.kind)
														? k.suits
														: 'Switched off on this instance (Settings → SCIM).'}
												</Typography.Text>
											</Radio>
										))}
									</Flex>
								</Radio.Group>
							</Form.Item>
							{kind === 'static_token' && (
								<Form.Item
									name="lifetimeDays"
									label="Lifetime"
									extra="After it the token is refused. Replacing it before then causes no outage."
								>
									<Select<90 | 365>
										style={{ width: 160 }}
										options={[
											{ label: '1 year', value: 365 },
											{ label: '90 days', value: 90 }
										]}
									/>
								</Form.Item>
							)}
							{kind === 'key' && (
								<>
									<Form.Item
										name="keySource"
										label="Public keys"
									>
										<Radio.Group
											options={[
												{ label: 'Paste a key set', value: 'jwks' },
												{ label: 'Fetch from a URL', value: 'jwksUri' }
											]}
										/>
									</Form.Item>
									{keySource === 'jwksUri' ? (
										<Form.Item
											name="jwksUri"
											label="JWKS URI"
											rules={[{ required: true, type: 'url' }]}
										>
											<Input autoComplete="off" />
										</Form.Item>
									) : (
										<Form.Item
											name="jwksText"
											label="JWKS"
											tooltip="Public keys only. A private or symmetric key is refused."
											rules={[
												{ required: true },
												{
													validator: async (
														_rule,
														text: string | undefined
													) => {
														if (text?.trim()) parseJwks(text);
													}
												}
											]}
										>
											<Input.TextArea
												rows={6}
												spellCheck={false}
											/>
										</Form.Item>
									)}
									<Form.Item
										name="signingAlg"
										label="Signing algorithm"
										tooltip="Optional. The algorithm the directory signs its client assertions with."
									>
										<Input
											autoComplete="off"
											placeholder="RS256"
										/>
									</Form.Item>
								</>
							)}
						</>
					)}
				</>
			)
		},
		{
			title: 'Connect',
			content: created && (
				<Flex
					vertical
					gap={16}
				>
					<Typography.Paragraph>
						Give {guidance?.displayName ?? 'the directory'} these values
						{guidance && guidance.id !== 'generic'
							? ', under the names it uses'
							: ''}
						.
					</Typography.Paragraph>
					<Descriptions
						column={1}
						size="small"
						bordered
						items={[
							{
								label: guidance?.labels.scimBaseUrl ?? 'SCIM base URL',
								children: <Copyable value={created.scimBaseUrl} />
							},
							{
								label: guidance?.labels.tokenEndpoint ?? 'Token endpoint',
								children: <Copyable value={created.tokenEndpoint} />
							},
							{
								label: guidance?.labels.clientId ?? 'Client id',
								children: <Copyable value={created.clientId} />
							},
							{ label: 'Scope', children: <Copyable value={created.scope} /> }
						]}
					/>
					{guidance?.pitfalls.map((pitfall) => (
						<Alert
							key={pitfall}
							type="info"
							showIcon
							title={pitfall}
						/>
					))}
					<div>
						<Button onClick={() => void copySetup()}>
							Copy setup details (without the secret)
						</Button>
					</div>
					<div aria-live="polite">
						{firstRequest ? (
							<Typography.Text type="success">
								<CheckCircleOutlined /> {created.displayName} made its first
								request at {new Date(firstRequest).toLocaleTimeString()}.
							</Typography.Text>
						) : gaveUp ? (
							<Typography.Text type="secondary">
								No request from the directory yet. Check the base URL and the
								credential in its settings, and start a provisioning run there;
								the connection's page shows when it arrives.
							</Typography.Text>
						) : (
							<Typography.Text type="secondary">
								<LoadingOutlined /> Waiting for the directory's first request…
							</Typography.Text>
						)}
					</div>
				</Flex>
			)
		}
	];

	return (
		<Drawer
			open
			size="large"
			title="New provisioning connection"
			onClose={close}
			mask={{ closable: false }}
			destroyOnHidden
			footer={
				<Flex
					justify="space-between"
					gap={8}
				>
					<Button onClick={close}>{created ? 'Close' : 'Cancel'}</Button>
					<Flex gap={8}>
						{step > 0 && step < 3 && (
							<Button onClick={() => setStep((s) => s - 1)}>Back</Button>
						)}
						{step < 2 && (
							<Button
								type="primary"
								onClick={() => void next()}
							>
								Next
							</Button>
						)}
						{step === 2 && (
							<Button
								type="primary"
								loading={busy}
								disabled={safeguard === undefined}
								onClick={() => void next()}
							>
								Create connection
							</Button>
						)}
						{step === 3 && !revealed && !keyIssued && (
							<>
								<Button onClick={() => setStep(4)}>Issue later</Button>
								<Button
									type="primary"
									loading={busy}
									disabled={!kind}
									onClick={() => void issue()}
								>
									{kind === 'key' ? 'Issue key' : 'Generate'}
								</Button>
							</>
						)}
						{step === 3 && (revealed || keyIssued) && (
							<Button
								type="primary"
								disabled={!credentialDone}
								onClick={() => setStep(4)}
							>
								Continue
							</Button>
						)}
						{step === 4 && (
							<Button
								type="primary"
								onClick={finish}
							>
								Finish
							</Button>
						)}
					</Flex>
				</Flex>
			}
		>
			<Steps
				size="small"
				current={step}
				items={steps.map((s) => ({ title: s.title }))}
				style={{ marginBottom: 24 }}
			/>
			{refusalAlert}
			<Form
				form={form}
				layout="vertical"
				requiredMark="optional"
			>
				{steps[step]?.content}
			</Form>
		</Drawer>
	);
}
