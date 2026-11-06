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
	type AddressesView
} from '../behind-proxy/appView.js';
import { KIND_LABELS } from '../behind-proxy/conditionsText.js';
import { groupsApi, type GroupView } from '../groups/groupShared.js';

interface ToolsForm {
	rows: { name: string; scopes: string[] }[];
	otherTools: Choice;
	withoutMethod: Choice;
}

function formOf(tools: ToolsTableView | undefined): ToolsForm {
	return {
		rows: (tools?.rows ?? []).map((row) => ({
			name: row.name,
			scopes: [...row.scopes]
		})),
		otherTools: tools?.otherTools ?? 'refuse',
		withoutMethod: tools?.withoutMethod ?? 'refuse'
	};
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
	onClose,
	onSaved
}: {
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
	useEffect(() => {
		if (!byProxy) return;
		void request<{ groups: GroupView[] }>('GET', groupsApi(bucketId)).then(
			(result) => {
				if (result.ok) setGroups(result.data.groups);
			}
		);
	}, [bucketId, byProxy]);

	async function save(values: ToolsForm) {
		const after: ToolsTableView = {
			rows: values.rows.map((row) => ({
				name: row.name,
				scopes: row.scopes
			})),
			otherTools: values.otherTools,
			withoutMethod: values.withoutMethod,
			...(byProxy && conditions.length > 0
				? {
						access: {
							conditions,
							...(zone ? { timeZone: zone } : {})
						}
					}
				: {})
		};
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
			/* The edge names a group condition's groups `groups`, as an app's rule does. */
			const body = after.access
				? {
						...after,
						access: {
							...after.access,
							conditions: after.access.conditions.map((c) =>
								c.kind === 'group' ? { kind: 'group', groups: c.groupIds } : c
							)
						}
					}
				: after;
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
							unavailable={
								addressesProven(addresses)
									? {}
									: {
											network: `${KIND_LABELS.network} is available once your proxy shows it passes people's addresses: finish "Your proxy passes people's addresses" in this API's Connect first.`
										}
							}
							onChange={(next) => {
								setRefusal(null);
								setConditions(next);
							}}
						/>
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
										No tools listed. Every tool needs only a valid token.
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
											rules={[
												{
													required: true,
													type: 'array',
													min: 1,
													message: 'Pick at least one scope'
												}
											]}
										>
											<Select
												mode="multiple"
												options={scopeOptions}
												placeholder="Scopes of this API"
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
								))}
								<div>
									<Button
										icon={<PlusOutlined />}
										onClick={() => add({ name: '', scopes: [] })}
									>
										Add tool
									</Button>
								</div>
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
										label: 'Let them in: they can call any tool'
									}
								]}
							/>
						</Form.Item>
					</div>
				</Form>

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
