import { useState } from 'react';
import {
	Alert,
	Button,
	Card,
	Drawer,
	Input,
	Select,
	Switch,
	Tooltip,
	Typography
} from 'antd';
import { DeleteOutlined, PlusOutlined } from '@ant-design/icons';
import {
	RAR_FIELDS,
	RAR_LIST_FIELDS,
	buildRarTypes,
	parseRarTypes,
	rarTypeIssues,
	type RarField,
	type RarType
} from './model.js';

const FIELD_HELP: Record<RarField, string> = {
	actions: 'What the client may do — "initiate", "read".',
	locations: 'Which resource the request is aimed at, as a URI.',
	datatypes: 'What kind of data is being reached.',
	privileges: 'The level of access being asked for.',
	identifier:
		'Which specific resource — an account number, say. Single-valued, so it can only be required.'
};

/*
 * The authorization details types this server accepts.
 *
 * A form, not a JSON field, because the descriptor's shape is fully enumerable and the raw textarea
 * it replaces let an operator express things the server refuses: a field name that does not exist, or
 * permitted values on `identifier`, which is single-valued. Both were accepted by the page and
 * reported as a 422 after saving, with the only on-screen feedback being "Not valid JSON yet" —
 * which spoke about the syntax and never about the rules.
 *
 * Two rules are enforced by construction here rather than checked: the five field names are a fixed
 * list, and permitted values are only offered for the four list-valued ones. The rest are reported
 * by `rarTypeIssues`, which is held to `validateConfiguration` itself by test — the server remains
 * the authority, the form only aims to agree with it early enough to be useful.
 *
 * Edits land in the page's values immediately rather than on closing the drawer, so the save bar
 * counts them and the review drawer shows them like any other pending change. A structured editor
 * that kept its own draft would be a second place where unsaved state lives.
 */
export function RarTypesField({
	value,
	enabled,
	disabled,
	onChange
}: {
	value: unknown;
	enabled: boolean;
	disabled: boolean;
	onChange: (types: Record<string, unknown>) => void;
}) {
	const [open, setOpen] = useState(false);
	const types = parseRarTypes(value);
	const issues = rarTypeIssues(types, enabled);

	const commit = (next: RarType[]) => onChange(buildRarTypes(next));
	const update = (index: number, patch: Partial<RarType>) =>
		commit(types.map((t, i) => (i === index ? { ...t, ...patch } : t)));

	return (
		<div style={{ width: '100%' }}>
			<div
				style={{
					display: 'flex',
					gap: 12,
					alignItems: 'center',
					flexWrap: 'wrap'
				}}
			>
				<Typography.Text>
					{types.length === 0
						? 'No types accepted'
						: `${types.length} ${types.length === 1 ? 'type' : 'types'} accepted`}
				</Typography.Text>
				<Button
					disabled={disabled}
					onClick={() => setOpen(true)}
				>
					{types.length === 0 ? 'Add a type' : 'Edit types'}
				</Button>
				{types.length > 0 && (
					<Typography.Text
						type="secondary"
						style={{ fontSize: 12 }}
					>
						{types.map((t) => t.label || t.id).join(', ')}
					</Typography.Text>
				)}
			</div>

			{issues.length > 0 && (
				<Alert
					type="warning"
					showIcon
					style={{ marginTop: 8 }}
					message={
						issues.length === 1
							? issues[0]
							: `${issues.length} things to fix before this can be saved`
					}
					description={
						issues.length > 1 ? (
							<ul style={{ margin: 0, paddingLeft: 18 }}>
								{issues.map((issue) => (
									<li key={issue}>{issue}</li>
								))}
							</ul>
						) : undefined
					}
				/>
			)}

			<Drawer
				title="Authorization details types"
				open={open}
				width={720}
				onClose={() => setOpen(false)}
				extra={
					<Button
						icon={<PlusOutlined />}
						onClick={() =>
							commit([
								...types,
								{
									id: '',
									label: '',
									fields: {},
									allowUnknownFields: false
								}
							])
						}
					>
						Add type
					</Button>
				}
			>
				<Typography.Paragraph type="secondary">
					A client names one of these in <code>authorization_details</code>, and
					its label is what the consent screen shows the person approving it.
					Constraints are optional — a type with none accepts any value for the
					fields RFC 9396 defines.
				</Typography.Paragraph>

				{types.length === 0 && (
					<Typography.Text type="secondary">
						No types yet. Rich Authorization Requests cannot be switched on
						until there is at least one.
					</Typography.Text>
				)}

				{types.map((t, index) => (
					<Card
						key={index}
						size="small"
						style={{ marginBottom: 16 }}
						title={t.label || t.id || 'New type'}
						extra={
							<Button
								danger
								type="text"
								icon={<DeleteOutlined />}
								onClick={() => commit(types.filter((_, i) => i !== index))}
							>
								Remove
							</Button>
						}
					>
						<div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
							<label>
								<Typography.Text strong>Type identifier</Typography.Text>
								<Input
									placeholder="https://scheme.example/payment"
									status={t.id.trim() === '' ? 'error' : undefined}
									value={t.id}
									onChange={(e) => update(index, { id: e.target.value })}
								/>
								<Typography.Text
									type="secondary"
									style={{ fontSize: 12 }}
								>
									What a client sends as the <code>type</code>. Usually a URI
									you control.
								</Typography.Text>
							</label>

							<label>
								<Typography.Text strong>Label</Typography.Text>
								<Input
									placeholder="Initiate a payment"
									status={t.label.trim() === '' ? 'error' : undefined}
									value={t.label}
									onChange={(e) => update(index, { label: e.target.value })}
								/>
								<Typography.Text
									type="secondary"
									style={{ fontSize: 12 }}
								>
									Shown on the consent screen, so write it for the person
									approving it rather than for the client.
								</Typography.Text>
							</label>

							<div>
								<Typography.Text strong>Constraints</Typography.Text>
								{RAR_FIELDS.map((field) => {
									const constraint = t.fields[field];
									const isList = (
										RAR_LIST_FIELDS as readonly string[]
									).includes(field);
									return (
										<div
											key={field}
											style={{
												display: 'flex',
												gap: 12,
												alignItems: 'center',
												flexWrap: 'wrap',
												padding: '6px 0'
											}}
										>
											<Switch
												size="small"
												checked={constraint !== undefined}
												onChange={(on) =>
													update(index, {
														fields: on
															? { ...t.fields, [field]: {} }
															: Object.fromEntries(
																	Object.entries(t.fields).filter(
																		([name]) => name !== field
																	)
																)
													})
												}
											/>
											<Tooltip title={FIELD_HELP[field]}>
												<Typography.Text code>{field}</Typography.Text>
											</Tooltip>
											{constraint && (
												<>
													<Switch
														size="small"
														checked={constraint.required === true}
														onChange={(required) =>
															update(index, {
																fields: {
																	...t.fields,
																	[field]: { ...constraint, required }
																}
															})
														}
													/>
													<Typography.Text type="secondary">
														required
													</Typography.Text>
													{/*
													 * Permitted values are offered for the four list-valued fields only.
													 * `identifier` is single-valued, so the server refuses `allowed` on
													 * it — and this is where that rule is enforced rather than checked.
													 */}
													{isList && (
														<Select
															mode="tags"
															size="small"
															style={{ minWidth: 220 }}
															placeholder="any value permitted"
															value={constraint.allowed ?? []}
															onChange={(allowed: string[]) =>
																update(index, {
																	fields: {
																		...t.fields,
																		[field]: {
																			...constraint,
																			allowed: allowed.length
																				? allowed
																				: undefined
																		}
																	}
																})
															}
														/>
													)}
												</>
											)}
										</div>
									);
								})}
							</div>

							<div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
								<Switch
									size="small"
									checked={t.allowUnknownFields}
									onChange={(allowUnknownFields) =>
										update(index, { allowUnknownFields })
									}
								/>
								<Typography.Text>
									Accept fields this type does not describe
								</Typography.Text>
								<Typography.Text
									type="secondary"
									style={{ fontSize: 12 }}
								>
									Off means a request carrying anything else is refused.
								</Typography.Text>
							</div>
						</div>
					</Card>
				))}
			</Drawer>
		</div>
	);
}
