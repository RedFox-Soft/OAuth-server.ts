import { useState } from 'react';
import {
	Alert,
	Button,
	Card,
	Drawer,
	Flex,
	Form,
	Input,
	Radio,
	Select,
	Steps,
	Switch,
	Typography
} from 'antd';
import { ApiOutlined } from '@ant-design/icons';
/* The login page's own marks, not a second copy: one table, corrected in one place. */
import { providerMark } from '../../../../interactions/providerMark.js';
import { MICROSOFT_SHARED_TENANTS } from '../../../../consts/known_providers.js';
import { request } from '../../frame/request.js';
import { useFeedback } from '../../frame/feedback.js';
import { useNavigate } from '../../frame/router.js';
import { providerHref } from '../../frame/routes.js';
import {
	federationApi,
	type Guidance,
	type PresentedProvider
} from './providerTypes.js';

/*
 * Connecting an identity provider, as four steps in a side panel (specs/084 US1).
 *
 * The last step is the reason the wizard exists. Whether a provider creates an account for anyone who signs
 * in through it decides who can enter the bucket — it ignores a closed Sign-up — and it used to be a default
 * nobody chose. Here Create cannot be pressed until the question has an answer, and the answer that opens the
 * bucket says what it opens.
 *
 * Nothing is created before Create, so Back and Next lose nothing and closing the panel leaves no trace.
 */

/* "Other OIDC provider": configured field by field rather than from the catalogue. */
const OTHER = '__other__';

/*
 * The option value standing for "I will type it myself". A sentinel is needed because the choice and the
 * value it decides are the same field: picking the broad answer *is* the value, while picking the narrow
 * one only says that a value is coming.
 */
const SUPPLY_IT = '__supply__';

type Values = Record<string, unknown> & {
	id?: string;
	displayName?: string;
	issuer?: string;
	clientId?: string;
	clientSecret?: string;
	provisioning?: 'jit' | 'existing_only';
	allowedEmailDomains?: string[];
	emailTrusted?: boolean;
};

const TRUST_FIELDS = ['provisioning', 'allowedEmailDomains', 'emailTrusted'];

const NOT_ON_PLAN =
	"Not included on this project's plan: enterprise sign-in needs a larger plan.";

/*
 * Whether an answer to a provider's question binds it to one organisation's directory — Microsoft's "only people in
 * one organisation" — which a plan counts as enterprise sign-in (lib/plans/provider.ts).
 */
function enterpriseChoice(name: string, value: string | null): boolean {
	return (
		name === 'tenant' &&
		(value === null || !MICROSOFT_SHARED_TENANTS.includes(value.toLowerCase()))
	);
}

export function ProviderWizard({
	bucketId,
	guidance,
	registrationOpen,
	consoleBucket,
	enterpriseSignIn = true,
	start,
	onClose
}: {
	bucketId: string;
	guidance: Guidance[];
	registrationOpen: boolean;
	consoleBucket: boolean;
	/*
	 * False on a plan without enterprise sign-in (specs/102): a generic provider and Microsoft for one organisation
	 * are shown as not included rather than left to a refusal at the last step.
	 */
	enterpriseSignIn?: boolean;
	/* A tile pressed on the empty state opens the panel at step two with that provider chosen. */
	start?: string;
	onClose: () => void;
}) {
	const feedback = useFeedback();
	const navigate = useNavigate();
	const [form] = Form.useForm<Values>();
	const [chosen, setChosen] = useState<string | null>(start ?? null);
	const [step, setStep] = useState(start ? 1 : 0);
	const [saving, setSaving] = useState(false);
	// The server's refusal, shown in the step it concerns rather than as a toast over the panel.
	const [refusal, setRefusal] = useState<{
		step: number;
		message: string;
	} | null>(null);
	const provisioning = Form.useWatch('provisioning', form);

	const entry = guidance.find((g) => g.catalogueId === chosen) ?? null;
	const other = chosen === OTHER;
	const callback = guidance.at(0);
	const name = entry?.displayName ?? 'your provider';

	function choose(id: string) {
		const picked = guidance.find((g) => g.catalogueId === id);
		if (picked?.alreadyConnected && picked.existingProviderId) {
			onClose();
			void navigate(providerHref(bucketId, picked.existingProviderId));
			return;
		}
		form.resetFields();
		setRefusal(null);
		setChosen(id);
		setStep(1);
	}

	const valueFields = (): string[] =>
		other
			? ['id', 'displayName', 'issuer', 'clientId', 'clientSecret']
			: [
					...(entry?.choices.map((c) => `choice:${c.name}`) ?? []),
					...(entry?.requiredValues
						.filter((v) => !entry.choices.some((c) => c.name === v.name))
						.map((v) => v.name) ?? [])
				];

	async function next() {
		if (step === 2) {
			try {
				await form.validateFields(valueFields());
			} catch {
				return;
			}
		}
		setRefusal(null);
		setStep((s) => s + 1);
	}

	async function create() {
		try {
			await form.validateFields(TRUST_FIELDS);
		} catch {
			return;
		}
		const values = form.getFieldsValue(true) as Values;
		const body: Record<string, unknown> = {};
		if (other) {
			for (const key of [...valueFields(), ...TRUST_FIELDS]) {
				if (values[key] !== undefined) body[key] = values[key];
			}
		} else if (entry) {
			body.catalogueId = entry.catalogueId;
			for (const choice of entry.choices) {
				const picked = values[`choice:${choice.name}`];
				// "I will type it myself" leaves the field to the value typed beside it; any other answer is the value.
				if (picked !== SUPPLY_IT && picked !== undefined)
					body[choice.name] = picked;
			}
			for (const key of [...valueFields(), ...TRUST_FIELDS]) {
				if (!key.startsWith('choice:') && values[key] !== undefined) {
					body[key] = values[key];
				}
			}
		}
		setSaving(true);
		try {
			const result = await request<PresentedProvider>(
				'POST',
				federationApi(bucketId),
				body
			);
			if (!result.ok) {
				if (result.status >= 500 || result.error.error_reference) {
					feedback.failed(result);
					return;
				}
				const field = result.error.field;
				const trustStep = field !== undefined && TRUST_FIELDS.includes(field);
				setRefusal({ step: trustStep ? 3 : 2, message: result.error.message });
				setStep(trustStep ? 3 : 2);
				if (field) {
					form.setFields([{ name: field, errors: [result.error.message] }]);
				}
				return;
			}
			feedback.done(`Identity provider ${result.data.displayName} connected.`);
			onClose();
			void navigate(providerHref(bucketId, result.data.id));
		} finally {
			setSaving(false);
		}
	}

	async function copy(uri: string) {
		try {
			await navigator.clipboard.writeText(uri);
			feedback.done('Callback address copied.');
		} catch {
			feedback.refused({
				error: 'clipboard',
				message:
					'The address could not be copied. Select it and copy it by hand.'
			});
		}
	}

	const refusalHere = (n: number) =>
		refusal?.step === n ? (
			<Alert
				type="error"
				showIcon
				style={{ marginBottom: 16 }}
				title="The provider was not created"
				description={refusal.message}
			/>
		) : null;

	const choose_step = (
		<Flex
			vertical
			gap={12}
		>
			<Typography.Paragraph>
				Which provider should people of this project sign in with?
			</Typography.Paragraph>
			<ProviderTiles
				guidance={guidance}
				enterpriseSignIn={enterpriseSignIn}
				onChoose={choose}
			/>
		</Flex>
	);

	const register_step = callback && (
		<>
			{entry ? (
				<>
					<Typography.Paragraph>
						Do this at{' '}
						<Typography.Link
							href={entry.consoleUrl}
							target="_blank"
							rel="noreferrer"
						>
							{entry.displayName}
						</Typography.Link>
						, then come back with the {entry.requiredValues.length} values it
						gives you.
					</Typography.Paragraph>
					<ol style={{ paddingLeft: 20, marginBottom: 16 }}>
						{entry.steps.map((s) => (
							<li
								key={s}
								style={{ marginBottom: 6 }}
							>
								{s}
							</li>
						))}
					</ol>
				</>
			) : (
				<Typography.Paragraph>
					Register an application (a "client") at your provider, with the
					redirect address below, and note its client id and secret.
				</Typography.Paragraph>
			)}
			<Typography.Paragraph style={{ marginBottom: 4 }}>
				<strong>The redirect address to register</strong>
			</Typography.Paragraph>
			<Flex
				gap={8}
				align="center"
				wrap
				style={{ marginBottom: 4 }}
			>
				<Typography.Text code>{callback.callbackUri}</Typography.Text>
				<Button
					size="small"
					onClick={() => void copy(callback.callbackUri)}
				>
					Copy
				</Button>
			</Flex>
			<Typography.Paragraph type="secondary">
				Paste it exactly. Providers match this address character for character,
				and a mismatch is refused on their page rather than here.
			</Typography.Paragraph>
			{callback.callbackStability === 'provisional' && (
				<Alert
					type="warning"
					showIcon
					title="This address will change"
					description="This project has no address of its own, so the address above is built from its internal id. If the project later gets a path or a host, it changes, and the provider must then be given the new one."
				/>
			)}
		</>
	);

	const values_step = (
		<>
			{refusalHere(2)}
			{other ? (
				<>
					<Form.Item
						name="id"
						label="Id"
						extra="Can't be changed later. It appears in the sign-in address. Lower-case letters, digits and hyphens."
						rules={[{ required: true }]}
					>
						<Input
							placeholder="acme-sso"
							autoComplete="off"
						/>
					</Form.Item>
					<Form.Item
						name="displayName"
						label="Button label"
						rules={[{ required: true }]}
					>
						<Input placeholder="Acme SSO" />
					</Form.Item>
					<Form.Item
						name="issuer"
						label="Issuer"
						extra="Checked when you create it: its discovery document must be reachable and name this issuer. It can't be changed afterwards."
						rules={[{ required: true }]}
					>
						<Input placeholder="https://idp.acme.com" />
					</Form.Item>
					<Form.Item
						name="clientId"
						label="Client id"
						rules={[{ required: true }]}
					>
						<Input autoComplete="off" />
					</Form.Item>
					<Form.Item
						name="clientSecret"
						label="Client secret"
						extra="Stored, and never shown again."
						rules={[{ required: true }]}
					>
						<Input.Password autoComplete="new-password" />
					</Form.Item>
				</>
			) : (
				entry && (
					<>
						{/*
						 * A question the provider forces before its values mean anything, with **no option
						 * preselected**: a default would be this console choosing who may sign in.
						 */}
						{entry.choices.map((choice) => (
							<Form.Item
								key={choice.name}
								name={`choice:${choice.name}`}
								label={choice.question}
								rules={[{ required: true }]}
							>
								<Select
									options={choice.options.map((option) => {
										const excluded =
											!enterpriseSignIn &&
											enterpriseChoice(choice.name, option.value);
										return {
											value: option.value ?? SUPPLY_IT,
											label: option.label,
											title: excluded ? NOT_ON_PLAN : option.consequence,
											disabled: excluded
										};
									})}
									optionRender={(option) => (
										<div>
											<div>{option.label}</div>
											<Typography.Text
												type="secondary"
												style={{ fontSize: 12, whiteSpace: 'normal' }}
											>
												{option.data.title}
											</Typography.Text>
										</div>
									)}
								/>
							</Form.Item>
						))}
						{/*
						 * `autoComplete` is off on all of them: these are an upstream's credentials, never the
						 * administrator's own, and without it the browser reads an identifier beside a secret as
						 * a sign-in form and fills both from its password store.
						 */}
						{entry.requiredValues
							.filter((v) => !entry.choices.some((c) => c.name === v.name))
							.map((value) => (
								<Form.Item
									key={value.name}
									name={value.name}
									label={value.label}
									tooltip={value.hint}
									rules={[{ required: true }]}
								>
									{value.secret ? (
										value.name === 'signingKey' ? (
											<Input.TextArea
												rows={4}
												autoComplete="off"
												placeholder="-----BEGIN PRIVATE KEY-----"
											/>
										) : (
											<Input.Password autoComplete="new-password" />
										)
									) : (
										<Input autoComplete="off" />
									)}
								</Form.Item>
							))}
					</>
				)
			)}
		</>
	);

	const trust_step = (
		<>
			{refusalHere(3)}
			<Form.Item
				name="provisioning"
				label="Someone signs in with this provider for the first time. What happens?"
				rules={[{ required: true, message: 'Choose who may sign in.' }]}
			>
				<Radio.Group>
					<Flex
						vertical
						gap={8}
					>
						<Radio value="existing_only">
							Only people who already have an account here
						</Radio>
						<Radio value="jit">Create an account for them</Radio>
					</Flex>
				</Radio.Group>
			</Form.Item>
			{provisioning === 'jit' && (
				<Alert
					type="warning"
					showIcon
					style={{ marginBottom: 16 }}
					title={`Anyone ${name} lets sign in gets an account here`}
					description={
						consoleBucket
							? 'On the console, a new account also needs sign-up open on this project; it gets a personal team and never the super administrator privilege.'
							: registrationOpen
								? 'Limit it with email domains below if only one organisation should get in.'
								: "This happens even though this project's Sign-up is closed. Limit it with email domains below if only one organisation should get in."
					}
				/>
			)}
			<Form.Item
				name="allowedEmailDomains"
				label="Only these email domains"
				extra="Empty means any address the provider vouches for."
			>
				<Select
					mode="tags"
					tokenSeparators={[' ', ',']}
					placeholder="acme.com"
				/>
			</Form.Item>
			<Form.Item
				name="emailTrusted"
				label="Link to an existing account with the same verified email"
				extra="Turn on only for a provider that really verifies addresses: whoever controls that address there gets the account here."
				valuePropName="checked"
				initialValue={!other}
			>
				<Switch />
			</Form.Item>
		</>
	);

	const steps = [
		{ title: 'Choose', content: choose_step },
		{ title: 'Register this project', content: register_step },
		{ title: 'Paste values', content: values_step },
		{ title: 'Who may sign in', content: trust_step }
	];

	return (
		<Drawer
			open
			size="large"
			title={
				chosen
					? `Connect ${other ? 'an OIDC provider' : name}`
					: 'New identity provider'
			}
			onClose={onClose}
			destroyOnHidden
			footer={
				<Flex
					justify="space-between"
					gap={8}
				>
					<Button onClick={onClose}>Cancel</Button>
					<Flex gap={8}>
						{step > 0 && (
							<Button onClick={() => setStep((s) => s - 1)}>Back</Button>
						)}
						{step > 0 && step < 3 && (
							<Button
								type="primary"
								onClick={() => void next()}
							>
								Next
							</Button>
						)}
						{step === 3 && (
							<Button
								type="primary"
								loading={saving}
								disabled={provisioning === undefined}
								onClick={() => void create()}
							>
								Create
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

/*
 * One tile per recognised provider and one for anything else: the choice an operator arrives knowing, so the
 * mark is what they scan for. Each tile is a real button named for what it does.
 */
export function ProviderTiles({
	guidance,
	enterpriseSignIn = true,
	onChoose
}: {
	guidance: Guidance[];
	/* False on a plan without enterprise sign-in: the generic tile is shown, disabled, saying why. */
	enterpriseSignIn?: boolean;
	onChoose: (catalogueId: string) => void;
}) {
	return (
		<Flex
			gap={12}
			wrap
		>
			{guidance.map((g) => (
				<Card
					key={g.catalogueId}
					size="small"
					style={{ width: 200 }}
				>
					<Button
						block
						icon={providerMark(g.catalogueId)}
						aria-label={
							g.alreadyConnected
								? `${g.displayName} is already connected — open it`
								: `Connect ${g.displayName}`
						}
						onClick={() => onChoose(g.catalogueId)}
					>
						{g.displayName}
					</Button>
					{g.alreadyConnected && (
						<Typography.Text
							type="secondary"
							style={{ fontSize: 12 }}
						>
							Already connected
						</Typography.Text>
					)}
				</Card>
			))}
			<Card
				size="small"
				style={{ width: 200 }}
			>
				<Button
					block
					icon={<ApiOutlined />}
					aria-label="Connect another OIDC provider"
					disabled={!enterpriseSignIn}
					onClick={() => onChoose(OTHER)}
				>
					Other OIDC provider
				</Button>
				{!enterpriseSignIn && (
					<Typography.Text
						type="secondary"
						style={{ fontSize: 12 }}
					>
						{NOT_ON_PLAN}
					</Typography.Text>
				)}
			</Card>
		</Flex>
	);
}

export { OTHER as OTHER_PROVIDER };
