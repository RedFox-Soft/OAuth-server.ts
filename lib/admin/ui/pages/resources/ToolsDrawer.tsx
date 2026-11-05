import { useState } from 'react';
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
	url,
	name,
	scopes,
	tools,
	checkedBy,
	onClose,
	onSaved
}: {
	/* The API's own admin address, `…/resources/:resourceId`. */
	url: string;
	name: string;
	/* The API's own scopes: the only ones a row may name. */
	scopes: readonly string[];
	tools: ToolsTableView | undefined;
	checkedBy: 'server' | 'proxy';
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

	async function save(values: ToolsForm) {
		const after: ToolsTableView = {
			rows: values.rows.map((row) => ({
				name: row.name,
				scopes: row.scopes
			})),
			otherTools: values.otherTools,
			withoutMethod: values.withoutMethod
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
			const result = await request('PATCH', url, { tools: after });
			if (!result.ok) {
				if (result.status >= 500) feedback.failed(result);
				else setRefusal(result.error.message);
				return;
			}
			feedback.done(`Tools for ${name} saved.`);
			onSaved();
		} finally {
			setSaving(false);
		}
	}

	return (
		<Drawer
			open
			size="large"
			title={`Tools: ${name}`}
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
