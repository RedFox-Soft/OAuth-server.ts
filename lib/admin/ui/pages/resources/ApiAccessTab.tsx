import { useEffect, useMemo, useState } from 'react';
import {
	Alert,
	Button,
	Card,
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
import { Link, useLeaveGuard } from '../../frame/router.js';
import { bucketHref } from '../../frame/routes.js';
import { SaveBar } from '../../settings/SaveBar.js';
import type { Change } from '../../settings/model.js';
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
import type { ApiView } from '../../../../behind_proxy/api_decision.js';
import { ConditionsEditor } from '../behind-proxy/ConditionsEditor.js';
import {
	addressesProven,
	networkFactsClosed
} from '../behind-proxy/appView.js';
import { conditionText, KIND_LABELS } from '../behind-proxy/conditionsText.js';
import type { GroupView } from '../groups/groupShared.js';
import { useCodeConsent, withConsent } from '../applications/codeConsent.js';
import {
	CLIENTS_PAGE,
	everyFields,
	everyMinutes,
	ResourceSignInFields,
	signInEveryText,
	type SignInFieldValues
} from './ResourceSignInFields.js';
import { ToolRowConditions } from './ToolRowConditions.js';
import { ApiCheckAccess } from './ApiCheckAccess.js';
import { usePasskeysAccepted } from '../signin/passkeysAccepted.js';
import { RefusedRecentlyCard } from '../RefusedRecentlyCard.js';
import { resourcesApi, type ResourceView } from './resourceView.js';

interface ToolsForm {
	rows: { name: string; scopes: string[]; conditions?: Condition[] }[];
	otherTools: Choice;
	withoutMethod: Choice;
}

/* One form for the tab: the sign-in requirement's fields sit beside the tools table's (specs/132 research R3). */
type AccessForm = ToolsForm & SignInFieldValues;

/* What the tab was last saved with; the baseline every change is measured against. */
interface Saved {
	requireCode: boolean;
	signInEveryMinutes: number | null;
	tools: ToolsTableView | undefined;
}

function formOf(saved: Saved): AccessForm {
	return {
		rows: (saved.tools?.rows ?? []).map((row) => ({
			name: row.name,
			scopes: [...row.scopes],
			conditions: (row.conditions ?? []).map((c) => ({ ...c }))
		})),
		otherTools: saved.tools?.otherTools ?? 'refuse',
		withoutMethod: saved.tools?.withoutMethod ?? 'refuse',
		requireCode: saved.requireCode,
		customUnit: 'days',
		...everyFields(saved.signInEveryMinutes)
	};
}

/* The table as stored, from the form and the API's own conditions; row and API conditions only where the proxy checks. */
function tableOf(
	values: ToolsForm,
	conditions: Condition[],
	zone: string | null,
	byProxy: boolean
): ToolsTableView {
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

/* The edge names a group condition's groups `groups`, as an app's rule does. */
function edgeConditions(conditions: readonly Condition[]) {
	return conditions.map((c) =>
		c.kind === 'group' ? { kind: 'group', groups: c.groupIds } : c
	);
}

function edgeTable(table: ToolsTableView) {
	return {
		...table,
		rows: table.rows.map((row) =>
			row.conditions
				? { ...row, conditions: edgeConditions(row.conditions) }
				: row
		),
		...(table.access
			? {
					access: {
						...table.access,
						conditions: edgeConditions(table.access.conditions)
					}
				}
			: {})
	};
}

function requirementText(requireCode: boolean, every: number | null): string {
	const parts = [
		...(requireCode ? ['Two-step sign-in'] : []),
		...(every !== null ? [signInEveryText(every)] : [])
	];
	return parts.length > 0 ? parts.join('; ') : 'none';
}

function viewOf(
	requireCode: boolean,
	every: number | null,
	tools: ToolsTableView | undefined
): ApiView {
	return {
		...(requireCode || every !== null
			? {
					signIn: {
						code: requireCode,
						...(every !== null ? { maxAgeSeconds: every * 60 } : {})
					}
				}
			: {}),
		...(tools ? { tools } : {})
	};
}

/*
 * Who may call an API and what each MCP tool needs (specs/132 Access): the sign-in requirement for every API (specs/130),
 * and for an API the proxy checks, the API's own conditions (specs/124), the tools table with each row's conditions
 * (specs/131) and the check of those rules under them. The two statements of what the table does not cover are always
 * on screen: a table that looks complete invites trusting it for reads and prompts, and for a body the proxy never sees.
 */
export function ApiAccessTab({
	bucketId,
	api,
	groups,
	writable,
	onChanged
}: {
	bucketId: string;
	api: ResourceView;
	groups: GroupView[];
	writable: boolean;
	onChanged: () => void;
}) {
	const url = resourcesApi(bucketId, api.identifier);
	const passkeys = usePasskeysAccepted(bucketId);
	const byProxy = api.checkedBy === 'proxy';
	const [form] = Form.useForm<AccessForm>();
	const feedback = useFeedback();
	const confirm = useConfirm();
	const signInConsent = useCodeConsent('api');
	const [saved, setSaved] = useState<Saved>(() => ({
		requireCode: api.requireCode,
		signInEveryMinutes: api.signInEveryMinutes,
		tools: api.tools
	}));
	const [conditions, setConditions] = useState<Condition[]>(() =>
		(api.tools?.access?.conditions ?? []).map((c) => ({ ...c }))
	);
	const [zone, setZone] = useState<string | null>(
		api.tools?.access?.timeZone ?? null
	);
	const [saving, setSaving] = useState(false);
	const [refusal, setRefusal] = useState<string | null>(null);
	const [gone, setGone] = useState(false);
	const [warnings, setWarnings] = useState<string[]>([]);
	/* The fields of a step that is hidden still count, so an emptied table keeps the choices it is saved with. */
	const values = Form.useWatch([], { form, preserve: true }) as
		AccessForm | undefined;
	const rows = values?.rows;
	const empty = (rows ?? saved.tools?.rows ?? []).length === 0;
	const scopeOptions = api.scopes.map((scope) => ({
		value: scope,
		label: scope
	}));
	const nameOf = (id: string) =>
		groups.find((g) => g.id === id)?.displayName ?? null;
	const groupOptions = groups.map((g) => ({
		id: g.id,
		displayName: g.displayName
	}));
	const countUrl = `/admin/api/projects/${encodeURIComponent(bucketId)}/attribute-matches`;
	const networkFactsOn = api.addresses?.networkFacts?.state !== 'off';
	/* A tool with conditions cannot be held to them by an app too old to name it (specs/131 research R3). */
	const toolConditions = (rows ?? []).some(
		(row) => (row.conditions ?? []).length > 0
	);
	const inherited = conditions.map((c) => ({
		from: 'the API',
		text: conditionText(c, nameOf)
	}));
	const networkUnavailable = addressesProven(api.addresses)
		? {}
		: {
				network: `${KIND_LABELS.network} is available once your proxy shows it passes people's addresses: finish "Your proxy passes people's addresses" on this API's Connect tab first.`
			};

	const savedTable = useMemo(
		() =>
			tableOf(
				formOf(saved),
				(saved.tools?.access?.conditions ?? []).map((c) => ({ ...c })),
				saved.tools?.access?.timeZone ?? null,
				byProxy
			),
		[saved, byProxy]
	);
	const editedTable =
		values?.rows !== undefined
			? tableOf({ ...formOf(saved), ...values }, conditions, zone, byProxy)
			: savedTable;
	const editedRequireCode =
		values?.requireCode === undefined ? saved.requireCode : values.requireCode;
	const editedEvery =
		values?.every === undefined
			? saved.signInEveryMinutes
			: everyMinutes(values);

	const changes: Change[] = [];
	if (
		editedRequireCode !== saved.requireCode ||
		editedEvery !== saved.signInEveryMinutes
	) {
		changes.push({
			key: 'signIn',
			label: 'Sign-in requirement',
			group: 'access',
			from: requirementText(saved.requireCode, saved.signInEveryMinutes),
			to: requirementText(editedRequireCode, editedEvery)
		});
	}
	if (
		JSON.stringify(savedTable.access ?? null) !==
		JSON.stringify(editedTable.access ?? null)
	) {
		changes.push({
			key: 'access',
			label: 'Who can call it',
			group: 'access',
			from:
				(savedTable.access?.conditions ?? [])
					.map((c) => conditionText(c, nameOf))
					.join('; ') || 'anyone who can sign in',
			to:
				(editedTable.access?.conditions ?? [])
					.map((c) => conditionText(c, nameOf))
					.join('; ') || 'anyone who can sign in'
		});
	}
	if (
		JSON.stringify([
			savedTable.rows,
			savedTable.otherTools,
			savedTable.withoutMethod
		]) !==
		JSON.stringify([
			editedTable.rows,
			editedTable.otherTools,
			editedTable.withoutMethod
		])
	) {
		changes.push({
			key: 'tools',
			label: 'What each MCP tool needs',
			group: 'access',
			from: `${String(savedTable.rows.length)} tools`,
			to: `${String(editedTable.rows.length)} tools`
		});
	}
	const dirty = changes.length > 0;
	useLeaveGuard(dirty, changes.length);

	const savedView = viewOf(
		saved.requireCode,
		saved.signInEveryMinutes,
		saved.tools
	);
	const editedView = dirty
		? viewOf(editedRequireCode, editedEvery, editedTable)
		: null;

	/* The form follows a save or a discard; it never re-reads the API while the administrator is editing. */
	useEffect(() => {
		form.setFieldsValue(formOf(saved));
	}, [form, saved]);

	function discard() {
		setRefusal(null);
		form.resetFields();
		form.setFieldsValue(formOf(saved));
		setConditions(
			(saved.tools?.access?.conditions ?? []).map((c) => ({ ...c }))
		);
		setZone(saved.tools?.access?.timeZone ?? null);
	}

	async function save() {
		try {
			await form.validateFields();
		} catch {
			return;
		}
		const requirementChanged =
			editedRequireCode !== saved.requireCode ||
			editedEvery !== saved.signInEveryMinutes;
		const tableChanged = changes.some(
			(c) => c.key === 'access' || c.key === 'tools'
		);
		if (tableChanged) {
			const widenings = toolWidenings(saved.tools, editedTable);
			if (widenings.length > 0) {
				const agreed = await confirm('resource.tools.widen', {
					target: api.name,
					consequences: widenings
				});
				if (!agreed) return;
			}
		}
		/* Sent only when it changed, so an edit of anything else is never previewed or audited as one (specs/130). */
		const body = {
			...(editedRequireCode !== saved.requireCode
				? { requireCode: editedRequireCode }
				: {}),
			...(editedEvery !== saved.signInEveryMinutes
				? { signInEveryMinutes: editedEvery }
				: {}),
			...(tableChanged ? { tools: edgeTable(editedTable) } : {})
		};
		setSaving(true);
		try {
			const result = await signInConsent(
				(consent) =>
					request<{
						warnings?: {
							machineClients: string[];
							pairwiseClients: string[];
						};
					}>('PATCH', url, withConsent(body, consent)),
				api.name
			);
			if (result === null) return;
			if (!result.ok) {
				if (result.status === 404) setGone(true);
				else if (result.status >= 500) feedback.failed(result);
				else setRefusal(result.error.message);
				return;
			}
			const found = result.data.warnings;
			setWarnings([
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
			]);
			feedback.done(`Access to ${api.name} saved.`);
			setSaved({
				requireCode: requirementChanged ? editedRequireCode : saved.requireCode,
				signInEveryMinutes: requirementChanged
					? editedEvery
					: saved.signInEveryMinutes,
				tools: tableChanged ? editedTable : saved.tools
			});
			onChanged();
		} finally {
			setSaving(false);
		}
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
			{!byProxy && (
				<Alert
					type="info"
					showIcon
					title="Your server checks this API's tokens"
					description="Only your proxy applies the tools table. It takes effect once the API is set to be checked by your proxy."
				/>
			)}
			{warnings.length > 0 && (
				<Alert
					type="warning"
					showIcon
					title="Saved. Some callers are now turned away"
					description={warnings.join(' ')}
					closable={{ onClose: () => setWarnings([]) }}
				/>
			)}
			{refusal && (
				<Alert
					type="error"
					showIcon
					title="Not saved"
					description={refusal}
				/>
			)}

			<Form<AccessForm>
				form={form}
				layout="vertical"
				initialValues={formOf(saved)}
				disabled={!writable}
				onValuesChange={() => setRefusal(null)}
			>
				<Flex
					vertical
					gap={16}
				>
					<Card title="Who can call it">
						<ResourceSignInFields
							checkedBy={api.checkedBy}
							every={values?.every}
							passkeys={passkeys}
						/>
						{byProxy && (
							<Flex
								vertical
								gap={12}
								style={{ marginTop: 16 }}
							>
								<ConditionsEditor
									conditions={conditions}
									kinds={API_ORDER}
									timeZone={zone}
									onTimeZone={setZone}
									groups={groupOptions}
									countUrl={countUrl}
									disabled={!writable}
									networkFactsOn={networkFactsOn}
									unavailable={networkUnavailable}
									onChange={(next) => {
										setRefusal(null);
										setConditions(next);
									}}
								/>
								{conditions.some((c) => c.kind === 'network' && c.facts) &&
									networkFactsClosed(api.addresses?.networkFacts) !== null && (
										<Alert
											type="error"
											showIcon
											title={networkFactsClosed(api.addresses?.networkFacts)}
										/>
									)}
								<Typography.Text type="secondary">
									With no condition, anyone who can sign in to this project can
									get a token for this API. A network condition is about the
									machine that calls the API: hosted assistants call from their
									own cloud, not from the person&apos;s network.
								</Typography.Text>
							</Flex>
						)}
					</Card>

					<Card title="What each MCP tool needs">
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
														groups={groupOptions}
														countUrl={countUrl}
														networkFactsOn={networkFactsOn}
														unavailable={networkUnavailable}
														nameOf={nameOf}
														disabled={!writable}
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
											A new or renamed tool on your MCP server gets the
											&quot;Any other tool&quot; answer until you add it here.
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
									A tool here has conditions, and an app too old to say which
									tool it calls can&apos;t be held to them, so such apps are
									refused. Today that includes many apps:{' '}
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
					</Card>
				</Flex>
			</Form>

			{byProxy && (
				<ApiCheckAccess
					bucketId={bucketId}
					scopes={api.scopes}
					saved={savedView}
					edited={editedView}
				/>
			)}
			{byProxy && (
				<RefusedRecentlyCard
					bucketId={bucketId}
					path={`${resourcesApi(bucketId, api.identifier)}/refusals`}
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

			{writable && (
				<SaveBar
					changes={changes}
					saving={saving}
					onSave={() => void save()}
					onDiscard={discard}
				/>
			)}
		</Flex>
	);
}
