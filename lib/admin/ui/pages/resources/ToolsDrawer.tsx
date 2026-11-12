import { useEffect, useState } from 'react';
import {
	Alert,
	Button,
	Drawer,
	Flex,
	Form,
	Input,
	Radio,
	Select,
	Typography
} from 'antd';
import { DeleteOutlined, PlusOutlined } from '@ant-design/icons';
import { request } from '../../frame/request.js';
import { useFeedback } from '../../frame/feedback.js';
import { useConfirm } from '../../frame/confirm.js';
import {
	HEADER_VALIDATING_VERSION,
	toolWidenings,
	type Choice,
	type ToolsTableView
} from '../../../../behind_proxy/tools.js';
import {
	API_ORDER,
	type Condition
} from '../../../../behind_proxy/conditions.js';
import { ConditionsEditor } from '../behind-proxy/ConditionsEditor.js';
import {
	addressesProven,
	networkFactsClosed,
	type AddressesView
} from '../behind-proxy/appView.js';
import { conditionText, KIND_LABELS } from '../behind-proxy/conditionsText.js';
import { CLIENTS_PAGE, signInEveryText } from './ResourceSignInFields.js';
import { ToolRowConditions } from './ToolRowConditions.js';
import { ApiCheckAccess } from './ApiCheckAccess.js';
import type { ApiView } from '../../../../behind_proxy/api_decision.js';
import { groupsApi, type GroupView } from '../groups/groupShared.js';

interface ToolsForm {
	rows: { name: string; scopes: string[]; conditions?: Condition[] }[];
	otherTools: Choice;
	withoutMethod: Choice;
}

function formOf(tools: ToolsTableView | undefined): ToolsForm {
	return {
		rows: (tools?.rows ?? []).map((row) => ({
			name: row.name,
			scopes: [...row.scopes],
			conditions: (row.conditions ?? []).map((c) => ({ ...c }))
		})),
		otherTools: tools?.otherTools ?? 'refuse',
		withoutMethod: tools?.withoutMethod ?? 'refuse'
	};
}

/* The edge names a group condition's groups `groups`, as an app's rule does. */
function edgeConditions(conditions: readonly Condition[]) {
	return conditions.map((c) =>
		c.kind === 'group' ? { kind: 'group', groups: c.groupIds } : c
	);
}

/*
 * What each MCP tool of an API needs, as its proxy checks it (specs/123 FR-013, FR-021). The two statements of what
 * the table does not cover are always on screen: a table that looks complete invites trusting it for reads and
 * prompts, and for a body the proxy never sees.
 */
export function ToolsDrawer({
	bucketId,
	url,
	name,
	scopes,
	tools,
	checkedBy,
	addresses,
	signIn,
	onClose,
	onSaved
}: {
	/* The API's sign-in requirement (specs/130), shown here and changed in the API's own form. */
	signIn?: { requireCode: boolean; signInEveryMinutes: number | null };
	bucketId: string;
	/* The API's own admin address, `…/resources/:resourceId`. */
	url: string;
	name: string;
	/* The API's own scopes: the only ones a row may name. */
	scopes: readonly string[];
	tools: ToolsTableView | undefined;
	checkedBy: 'server' | 'proxy';
	/* What the proxy's checks showed about the addresses it passes; a network condition waits for its proof. */
	addresses: AddressesView | undefined;
	onClose: () => void;
	onSaved: () => void;
}) {
	const [form] = Form.useForm<ToolsForm>();
	const feedback = useFeedback();
	const confirm = useConfirm();
	const [saving, setSaving] = useState(false);
	const [refusal, setRefusal] = useState<string | null>(null);
	const rows = Form.useWatch('rows', form) as ToolsForm['rows'] | undefined;
	const empty = (rows ?? tools?.rows ?? []).length === 0;
	const scopeOptions = scopes.map((scope) => ({ value: scope, label: scope }));
	/* Who may call the API at all (specs/124 FR-025): only where the proxy checks its tokens. */
	const byProxy = checkedBy === 'proxy';
	const [conditions, setConditions] = useState<Condition[]>(() =>
		(tools?.access?.conditions ?? []).map((c) => ({ ...c }))
	);
	const [zone, setZone] = useState<string | null>(
		tools?.access?.timeZone ?? null
	);
	const [groups, setGroups] = useState<GroupView[]>([]);
	const [warnings, setWarnings] = useState<string[]>([]);
	const nameOf = (id: string) =>
		groups.find((g) => g.id === id)?.displayName ?? null;
	/* A tool with conditions cannot be held to them by an app too old to name it (specs/131 research R3). */
	const toolConditions = (rows ?? []).some(
		(row) => (row.conditions ?? []).length > 0
	);
	const inherited = conditions.map((c) => ({
		from: 'the API',
		text: conditionText(c, nameOf)
	}));
	const networkUnavailable = addressesProven(addresses)
		? {}
		: {
				network: `${KIND_LABELS.network} is available once your proxy shows it passes people's addresses: finish "Your proxy passes people's addresses" in this API's Connect first.`
			};
	const savedView: ApiView = {
		...(signIn && (signIn.requireCode || signIn.signInEveryMinutes !== null)
			? {
					signIn: {
						code: signIn.requireCode,
						...(signIn.signInEveryMinutes !== null
							? { maxAgeSeconds: signIn.signInEveryMinutes * 60 }
							: {})
					}
				}
			: {}),
		...(tools ? { tools } : {})
	};
	const values = Form.useWatch([], form) as ToolsForm | undefined;
	const editedView: ApiView | null =
		values?.rows !== undefined
			? { ...savedView, tools: tableOf({ ...formOf(tools), ...values }) }
			: null;
	useEffect(() => {
		if (!byProxy) return;
		void request<{ groups: GroupView[] }>('GET', groupsApi(bucketId)).then(
			(result) => {
				if (result.ok) setGroups(result.data.groups);
			}
		);
	}, [bucketId, byProxy]);

	function tableOf(values: ToolsForm): ToolsTableView {
		return {
			rows: values.rows.map((row) => ({
				name: row.name,
				scopes: row.scopes,
				...(byProxy && (row.conditions ?? []).length > 0
					? { conditions: row.conditions }
					: {})
			})),
			otherTools: values.otherTools,
			withoutMethod: values.withoutMethod,
			/* Kept with only a zone too: the tool rows read their hours in it (specs/131 research R2). */
			...(byProxy && (conditions.length > 0 || zone)
				? {
						access: {
							conditions,
							...(zone ? { timeZone: zone } : {})
						}
					}
				: {})
		};
	}

	async function save(values: ToolsForm) {
		const after = tableOf(values);
		const widenings = toolWidenings(tools, after);
		if (widenings.length > 0) {
			const agreed = await confirm('resource.tools.widen', {
				target: name,
				consequences: widenings
			});
			if (!agreed) return;
		}
		setSaving(true);
		try {
			const body = {
				...after,
				rows: after.rows.map((row) =>
					row.conditions
						? { ...row, conditions: edgeConditions(row.conditions) }
						: row
				),
				...(after.access
					? {
							access: {
								...after.access,
								conditions: edgeConditions(after.access.conditions)
							}
						}
					: {})
			};
			const result = await request<{
				warnings?: { machineClients: string[]; pairwiseClients: string[] };
			}>('PATCH', url, { tools: body });
			if (!result.ok) {
				if (result.status >= 500) feedback.failed(result);
				else setRefusal(result.error.message);
				return;
			}
			const found = result.data.warnings;
			const lines = [
				...(found?.machineClients.length
					? [
							`Tokens issued to an application alone carry no person, so these are now turned away: ${found.machineClients.join(', ')}.`
						]
					: []),
				...(found?.pairwiseClients.length
					? [
							`These applications give people per-application identifiers, which the check cannot trace to a person, so their tokens are turned away: ${found.pairwiseClients.join(', ')}.`
						]
					: [])
			];
			feedback.done(`Access to ${name} saved.`);
			if (lines.length > 0) {
				setWarnings(lines);
				return;
			}
			onSaved();
		} finally {
			setSaving(false);
		}
	}

	return (
		<Drawer
			open
			size="large"
			title={byProxy ? `Access at your proxy: ${name}` : `Tools: ${name}`}
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
			<Flex
				vertical
				gap={16}
			>
				{checkedBy === 'server' && (
					<Alert
						type="info"
						showIcon
						title="Your server checks this API's tokens"
						description="Only your proxy applies this table. It takes effect once the API is set to be checked by your proxy."
					/>
				)}
				{warnings.length > 0 && (
					<Alert
						type="warning"
						showIcon
						title="Saved. Some callers are now turned away"
						description={warnings.join(' ')}
						action={
							<Button
								size="small"
								onClick={onSaved}
							>
								Close
							</Button>
						}
					/>
				)}
				{byProxy && (
					<>
						<Typography.Title level={5}>Who can call it</Typography.Title>
						{signIn &&
							(signIn.requireCode || signIn.signInEveryMinutes !== null) && (
								<Typography.Paragraph type="secondary">
									{[
										signIn.requireCode
											? 'A sign-in with a code from an authenticator app is required.'
											: null,
										signIn.signInEveryMinutes !== null
											? `${signInEveryText(signIn.signInEveryMinutes)}.`
											: null
									]
										.filter(Boolean)
										.join(' ')}{' '}
									Change it in Edit…
								</Typography.Paragraph>
							)}
						<ConditionsEditor
							conditions={conditions}
							kinds={API_ORDER}
							timeZone={zone}
							onTimeZone={setZone}
							groups={groups.map((g) => ({
								id: g.id,
								displayName: g.displayName
							}))}
							countUrl={`/admin/api/projects/${encodeURIComponent(bucketId)}/attribute-matches`}
							disabled={false}
							networkFactsOn={addresses?.networkFacts?.state !== 'off'}
							unavailable={networkUnavailable}
							onChange={(next) => {
								setRefusal(null);
								setConditions(next);
							}}
						/>
						{conditions.some((c) => c.kind === 'network' && c.facts) &&
							networkFactsClosed(addresses?.networkFacts) !== null && (
								<Alert
									type="error"
									showIcon
									title={networkFactsClosed(addresses?.networkFacts)}
								/>
							)}
						<Typography.Text type="secondary">
							With no condition, anyone who can sign in to this project can get
							a token for this API. A network condition is about the machine
							that calls the API: hosted assistants call from their own cloud,
							not from the person&apos;s network.
						</Typography.Text>
					</>
				)}
				{refusal && (
					<Alert
						type="error"
						showIcon
						title="Not saved"
						description={refusal}
					/>
				)}

				<Form<ToolsForm>
					form={form}
					layout="vertical"
					initialValues={formOf(tools)}
					onFinish={(values) => void save(values)}
					onValuesChange={() => setRefusal(null)}
				>
					<Typography.Title level={5}>
						What each MCP tool needs
					</Typography.Title>
					<Form.List name="rows">
						{(fields, { add, remove }) => (
							<Flex
								vertical
								gap={8}
							>
								{fields.length === 0 ? (
									<Typography.Text type="secondary">
										No tools listed. Every tool needs only a valid token, and
										the two choices below apply only once a tool is listed.
									</Typography.Text>
								) : (
									<Flex gap={8}>
										<Typography.Text
											type="secondary"
											style={{ flex: 1 }}
										>
											Tool
										</Typography.Text>
										<Typography.Text
											type="secondary"
											style={{ flex: 1.4 }}
										>
											Needs every one of
										</Typography.Text>
										<span style={{ width: 32 }} />
									</Flex>
								)}
								{fields.map((field) => (
									<Flex
										key={field.key}
										vertical
										gap={4}
									>
										<Flex
											gap={8}
											align="start"
										>
											<Form.Item
												name={[field.name, 'name']}
												style={{ flex: 1, marginBottom: 0 }}
												rules={[{ required: true, message: 'Name the tool' }]}
											>
												<Input
													placeholder="search_files"
													aria-label="Tool name"
												/>
											</Form.Item>
											<Form.Item
												name={[field.name, 'scopes']}
												style={{ flex: 1.4, marginBottom: 0 }}
												dependencies={[['rows', field.name, 'conditions']]}
												rules={[
													({ getFieldValue }) => ({
														validator(_rule, value: string[] | undefined) {
															/* A row with conditions may need no scope (specs/131). */
															const own = getFieldValue([
																'rows',
																field.name,
																'conditions'
															]) as Condition[] | undefined;
															return (value ?? []).length > 0 ||
																(own ?? []).length > 0
																? Promise.resolve()
																: Promise.reject(
																		new Error(
																			'Pick a scope, or give the tool a condition'
																		)
																	);
														}
													})
												]}
											>
												<Select
													mode="multiple"
													options={scopeOptions}
													placeholder={
														(rows?.[field.name]?.conditions ?? []).length > 0
															? 'None: its conditions only'
															: 'Scopes of this API'
													}
													aria-label="Scopes it needs"
												/>
											</Form.Item>
											<Button
												type="text"
												icon={<DeleteOutlined />}
												aria-label="Remove this tool"
												onClick={() => remove(field.name)}
											/>
										</Flex>
										{byProxy && (
											<Form.Item
												name={[field.name, 'conditions']}
												style={{ marginBottom: 8 }}
											>
												<ToolRowConditions
													inherited={inherited}
													timeZone={zone}
													onTimeZone={setZone}
													groups={groups.map((g) => ({
														id: g.id,
														displayName: g.displayName
													}))}
													countUrl={`/admin/api/projects/${encodeURIComponent(bucketId)}/attribute-matches`}
													networkFactsOn={
														addresses?.networkFacts?.state !== 'off'
													}
													unavailable={networkUnavailable}
													nameOf={nameOf}
												/>
											</Form.Item>
										)}
									</Flex>
								))}
								<div>
									<Button
										icon={<PlusOutlined />}
										onClick={() =>
											add({ name: '', scopes: [], conditions: [] })
										}
									>
										Add tool
									</Button>
								</div>
								{fields.length > 0 && (
									<Typography.Text type="secondary">
										A new or renamed tool on your MCP server gets the &quot;Any
										other tool&quot; answer until you add it here.
									</Typography.Text>
								)}
							</Flex>
						)}
					</Form.List>

					{/* Hidden rather than unmounted, so an emptied table keeps the choices it is saved with. */}
					<div style={{ display: empty ? 'none' : undefined, marginTop: 24 }}>
						<Form.Item
							name="otherTools"
							label="Any other tool"
						>
							<Radio.Group
								options={[
									{ value: 'refuse', label: 'Refused' },
									{ value: 'token', label: 'Needs only a valid token' }
								]}
							/>
						</Form.Item>
						<Typography.Paragraph type="secondary">
							Listing tools and starting a session always need only a valid
							token.
						</Typography.Paragraph>
						<Form.Item
							name="withoutMethod"
							label="Clients too old to say which tool they call"
							extra={`Clients that send no Mcp-Method header, or speak an MCP protocol older than ${HEADER_VALIDATING_VERSION}. Their servers never compare the headers with the body, so such a client could name one tool and call another.`}
						>
							<Radio.Group
								options={[
									{ value: 'refuse', label: 'Refuse them' },
									{
										value: 'token',
										label: 'Let them in: they can call any tool',
										disabled: toolConditions
									}
								]}
							/>
						</Form.Item>
						{toolConditions && (
							<Typography.Paragraph type="secondary">
								A tool here has conditions, and an app too old to say which tool
								it calls can&apos;t be held to them, so such apps are refused.
								Today that includes many apps:{' '}
								<Typography.Link
									href={CLIENTS_PAGE}
									target="_blank"
								>
									see which apps say which tool they call
								</Typography.Link>
								.
							</Typography.Paragraph>
						)}
					</div>
				</Form>

				{byProxy && (
					<ApiCheckAccess
						bucketId={bucketId}
						scopes={scopes}
						saved={savedView}
						edited={editedView}
					/>
				)}

				<Alert
					type="info"
					showIcon
					title="What this table does not cover"
					description={
						<ul style={{ margin: 0, paddingInlineStart: 20 }}>
							<li>
								Reading resources and getting prompts: they need only a valid
								token.
							</li>
							<li>
								A request whose Mcp-Name header and body disagree: your proxy
								cannot see the body, so your MCP server must still refuse it.
							</li>
						</ul>
					}
				/>
			</Flex>
		</Drawer>
	);
}
