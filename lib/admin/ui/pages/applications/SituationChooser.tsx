import { useEffect, useState } from 'react';
import {
	Alert,
	Button,
	Card,
	Flex,
	Form,
	Input,
	Modal,
	Select,
	Typography
} from 'antd';
import { request } from '../../frame/request.js';
import { useFeedback } from '../../frame/feedback.js';
import { Link, useNavigate } from '../../frame/router.js';
import { applicationHref, bucketHref } from '../../frame/routes.js';
import {
	SITUATIONS,
	devAddressProblem,
	originOf,
	type Situation,
	type SituationGroup
} from './situations.js';
import { buildBody, DEFAULT_VALUES, type FormValues } from './clientForm.js';
import { ClientFormFields } from './ClientFormFields.js';
import { handOff } from './handOff.js';

const GROUPS: { group: SituationGroup; title: string }[] = [
	{ group: 'people', title: 'People sign in to it' },
	{ group: 'machine', title: 'No one signs in — code calls an API' },
	{ group: 'resource', title: 'Your server accepts tokens' }
];

interface DeclaredApi {
	identifier: string;
	name?: string;
}

/* The second step's fields: what the situation derived, still editable. */
interface Details {
	clientName?: string;
	devAddress?: string;
	redirectUri?: string;
	postLogoutRedirectUri?: string;
	origin?: string;
	api?: string;
}

/*
 * "New application" (spec 107): a situation first, protocol second. The chosen situation only fills in the fields
 * of the ordinary create request; "Show all settings" and "Configure everything yourself" open the one full form.
 */
export function SituationChooser({
	bucketId,
	open,
	onClose,
	siblings
}: {
	bucketId: string;
	open: boolean;
	onClose: () => void;
	/* Other applications with browser origins, for the full form's copy-from list. */
	siblings: { label: string; origins: string[] }[];
}) {
	const navigate = useNavigate();
	const feedback = useFeedback();
	const [chosen, setChosen] = useState<Situation | null>(null);
	const [full, setFull] = useState(false);
	const [saving, setSaving] = useState(false);
	const [apis, setApis] = useState<DeclaredApi[] | null>(null);
	/*
	 * What each step's form opens with. Given as initial values rather than written into the form: a form is not
	 * mounted until its step renders, and a write before that reaches nothing.
	 */
	const [detailsInitial, setDetailsInitial] = useState<Details>({});
	const [fullInitial, setFullInitial] = useState<FormValues>(DEFAULT_VALUES);
	const [details] = Form.useForm<Details>();
	const [form] = Form.useForm<FormValues>();
	const devAddress = Form.useWatch('devAddress', details);

	const base = `/admin/api/projects/${encodeURIComponent(bucketId)}`;

	useEffect(() => {
		if (!open || chosen?.id !== 'service') return;
		void request<{ resources: DeclaredApi[] }>('GET', `${base}/resources`).then(
			(result) => {
				setApis(result.ok ? result.data.resources : []);
			}
		);
	}, [open, chosen, base]);

	function reset() {
		setChosen(null);
		setFull(false);
		setApis(null);
	}

	function close() {
		reset();
		onClose();
	}

	/* The fields a situation derives from where the app runs. */
	function derived(situation: Situation, devAddress: string): Details {
		const expansion = situation.expand?.(devAddress);
		return expansion
			? {
					redirectUri: expansion.redirectUris.at(0),
					postLogoutRedirectUri: expansion.postLogoutRedirectUris.at(0),
					origin: expansion.corsOrigins.at(0)
				}
			: {};
	}

	function choose(situation: Situation) {
		if (situation.id === 'resource') {
			close();
			void navigate(`${bucketHref(bucketId, 'apis')}?declare=1`);
			return;
		}
		setChosen(situation);
		if (situation.id === 'custom') {
			setFullInitial(DEFAULT_VALUES);
			setFull(true);
			return;
		}
		setDetailsInitial({
			devAddress: situation.devAddress,
			...derived(situation, situation.devAddress ?? '')
		});
	}

	/* Switches the chosen situation's answers into the full form, so nothing typed is lost. */
	function showAll() {
		if (!chosen?.expand) return;
		const values = details.getFieldsValue();
		const expansion = chosen.expand(values.devAddress ?? '');
		setFullInitial({
			...DEFAULT_VALUES,
			clientName: values.clientName,
			applicationType: expansion.applicationType,
			grantTypes: expansion.grantTypes,
			tokenEndpointAuthMethod: expansion.tokenEndpointAuthMethod,
			redirectUris: values.redirectUri ?? expansion.redirectUris.join('\n'),
			postLogoutRedirectUris:
				values.postLogoutRedirectUri ??
				expansion.postLogoutRedirectUris.join('\n'),
			corsOrigins: values.origin ? [values.origin] : expansion.corsOrigins
		});
		setFull(true);
	}

	async function create(body: Record<string, unknown>, api?: string) {
		setSaving(true);
		try {
			const result = await request<{ clientId: string; secret?: string }>(
				'POST',
				`${base}/clients`,
				body
			);
			if (!result.ok) {
				feedback.failed(result, full ? form : undefined);
				return;
			}
			feedback.done('Application created.');
			handOff(result.data.clientId, {
				...(result.data.secret ? { secret: result.data.secret } : {}),
				...(api ? { api } : {})
			});
			close();
			void navigate(applicationHref(bucketId, result.data.clientId));
		} finally {
			setSaving(false);
		}
	}

	async function submitSituation(values: Details) {
		if (!chosen?.expand) return;
		const expansion = chosen.expand(values.devAddress ?? '');
		await create(
			{
				clientName: values.clientName?.trim() || chosen.title,
				...expansion,
				...(values.redirectUri !== undefined
					? { redirectUris: values.redirectUri ? [values.redirectUri] : [] }
					: {}),
				...(values.postLogoutRedirectUri !== undefined
					? {
							postLogoutRedirectUris: values.postLogoutRedirectUri
								? [values.postLogoutRedirectUri]
								: []
						}
					: {}),
				...(values.origin !== undefined
					? { corsOrigins: values.origin ? [values.origin] : [] }
					: {})
			},
			values.api
		);
	}

	const peopleRedirect =
		chosen?.id === 'server' || chosen?.id === 'spa' || chosen?.id === 'native';
	const service = chosen?.id === 'service';
	const noApis = service && apis !== null && apis.length === 0;

	const step1 = (
		<Flex
			vertical
			gap={16}
		>
			{GROUPS.map(({ group, title }) => (
				<div key={group}>
					<Typography.Title level={5}>{title}</Typography.Title>
					<Flex
						wrap
						gap={12}
					>
						{SITUATIONS.filter(
							(s) => s.group === group && s.id !== 'custom'
						).map((s) => (
							<Card
								key={s.id}
								hoverable
								size="small"
								style={{ width: 260 }}
								onClick={() => choose(s)}
								role="button"
								tabIndex={0}
								onKeyDown={(e) => {
									if (e.key === 'Enter' || e.key === ' ') {
										e.preventDefault();
										choose(s);
									}
								}}
							>
								<Typography.Text strong>{s.title}</Typography.Text>
								<Typography.Paragraph
									type="secondary"
									style={{ margin: '4px 0' }}
								>
									{s.description}
								</Typography.Paragraph>
								<Typography.Text
									type="secondary"
									style={{ fontSize: 12 }}
								>
									{s.footnote}
								</Typography.Text>
							</Card>
						))}
					</Flex>
				</div>
			))}
			<Typography.Text type="secondary">
				Not sure? Most apps with a backend are a{' '}
				<Typography.Link
					onClick={() => {
						const server = SITUATIONS.find((s) => s.id === 'server');
						if (server) choose(server);
					}}
				>
					Web app with a server
				</Typography.Link>
				.{' '}
				<Typography.Link
					onClick={() => {
						const custom = SITUATIONS.find((s) => s.id === 'custom');
						if (custom) choose(custom);
					}}
				>
					Configure everything yourself
				</Typography.Link>
			</Typography.Text>
		</Flex>
	);

	const step2 = chosen && !full && (
		<Form<Details>
			key={chosen.id}
			form={details}
			initialValues={detailsInitial}
			layout="vertical"
			onFinish={(values) => void submitSituation(values)}
		>
			<Typography.Paragraph type="secondary">
				{chosen.title} — {chosen.footnote}
			</Typography.Paragraph>
			<Form.Item
				name="clientName"
				label="Name"
				extra="Shown in this console and on the consent page."
			>
				<Input placeholder={chosen.title} />
			</Form.Item>
			{chosen.devAddress !== undefined && (
				<Form.Item
					name="devAddress"
					label="Where does your app run while you develop?"
					rules={[
						{
							validator: async (_rule, value: string | undefined) => {
								const problem = devAddressProblem(value ?? '');
								if (problem) throw new Error(problem);
							}
						}
					]}
				>
					<Input
						placeholder={chosen.devAddress}
						onChange={(e) =>
							details.setFieldsValue(derived(chosen, e.target.value))
						}
					/>
				</Form.Item>
			)}
			{peopleRedirect && (
				<Form.Item
					name="redirectUri"
					label="Callback URL (redirect URI)"
					rules={[{ required: true, message: 'A callback URL is required.' }]}
					extra={
						chosen.id === 'server' ? (
							<Typography.Text type="secondary">
								Using Auth.js (NextAuth)? Its callback is{' '}
								<Typography.Text code>
									{originOf(devAddress ?? chosen.devAddress ?? '')}
									/api/auth/callback/foxauth
								</Typography.Text>{' '}
								for a provider with id{' '}
								<Typography.Text code>foxauth</Typography.Text>.
							</Typography.Text>
						) : chosen.id === 'native' ? (
							'Accepted on any port, as native apps pick one at run time. localhost and 127.0.0.1 are different addresses: use the one your app listens on.'
						) : (
							'Exact match: the address your app sends people back to after they sign in.'
						)
					}
				>
					<Input />
				</Form.Item>
			)}
			{(chosen.id === 'server' || chosen.id === 'spa') && (
				<Form.Item
					name="postLogoutRedirectUri"
					label="After sign-out, return to"
				>
					<Input />
				</Form.Item>
			)}
			{chosen.id === 'spa' && (
				<Form.Item
					name="origin"
					label="Browser origin"
					extra="The origin your app's browser code calls the token endpoint from."
				>
					<Input />
				</Form.Item>
			)}
			{service && apis === null && (
				<Typography.Text>Loading APIs…</Typography.Text>
			)}
			{noApis && (
				<Alert
					type="info"
					showIcon
					title="A service needs an API to call"
					description={
						<>
							Declare the API first, then come back.{' '}
							<Link href={`${bucketHref(bucketId, 'apis')}?declare=1`}>
								Declare an API
							</Link>
						</>
					}
				/>
			)}
			{service && apis !== null && apis.length > 0 && (
				<Form.Item
					name="api"
					label="Which API will it call?"
					rules={[{ required: true, message: 'Choose an API.' }]}
					extra="Its credential can obtain tokens for every API this project declares; this one is used in the example."
				>
					<Select
						options={apis.map((a) => ({
							label: a.name ? `${a.name} — ${a.identifier}` : a.identifier,
							value: a.identifier
						}))}
					/>
				</Form.Item>
			)}
		</Form>
	);

	const stepFull = full && (
		<Form<FormValues>
			key={`full-${chosen?.id ?? ''}`}
			form={form}
			layout="vertical"
			scrollToFirstError
			initialValues={fullInitial}
			onFinish={(values) => void create(buildBody(values))}
		>
			<ClientFormFields
				form={form}
				siblings={siblings}
			/>
		</Form>
	);

	function footerFor() {
		if (!chosen) {
			return [
				<Button
					key="cancel"
					onClick={close}
				>
					Cancel
				</Button>
			];
		}
		return [
			<Button
				key="back"
				onClick={reset}
			>
				Back
			</Button>,
			...(!full && chosen.expand
				? [
						<Button
							key="all"
							onClick={showAll}
						>
							Show all settings
						</Button>
					]
				: []),
			<Button
				key="create"
				type="primary"
				loading={saving}
				disabled={noApis}
				onClick={() => (full ? form.submit() : details.submit())}
			>
				Create application
			</Button>
		];
	}

	return (
		<Modal
			title={chosen ? `New application: ${chosen.title}` : 'New application'}
			open={open}
			onCancel={close}
			footer={footerFor()}
			width={chosen && !full ? 560 : 880}
			destroyOnHidden
		>
			{!chosen && step1}
			{step2}
			{stepFull}
		</Modal>
	);
}
