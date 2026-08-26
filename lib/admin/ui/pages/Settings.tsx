import { useEffect, useMemo, useState } from 'react';
import {
	Alert,
	Button,
	Card,
	Collapse,
	Form,
	Input,
	InputNumber,
	Select,
	Switch,
	Tag,
	Typography,
	message
} from 'antd';

// Mirrors SettingType in lib/admin/settings/catalog.ts. A type added there without a branch in
// `control()` below falls through to the plain text input, which cannot edit a structured value.
type SettingType =
	'boolean' | 'string' | 'enum' | 'number' | 'string-array' | 'json';

function JsonField({
	value,
	onChange
}: {
	value: unknown;
	onChange: (parsed: unknown) => void;
}) {
	const [text, setText] = useState(() => JSON.stringify(value ?? {}, null, 2));
	const [invalid, setInvalid] = useState(false);

	return (
		<div style={{ maxWidth: 520 }}>
			<Input.TextArea
				autoSize={{ minRows: 4, maxRows: 18 }}
				status={invalid ? 'error' : undefined}
				value={text}
				onChange={(e) => {
					const next = e.target.value;
					setText(next);
					try {
						onChange(JSON.parse(next));
						setInvalid(false);
					} catch {
						// Held locally until it parses: submitting a half-typed document would be refused by
						// the server for a reason the operator is in the middle of fixing.
						setInvalid(true);
					}
				}}
			/>
			{invalid ? (
				<Typography.Text type="danger">Not valid JSON yet</Typography.Text>
			) : null}
		</div>
	);
}
interface Descriptor {
	key: string;
	group: string;
	label: string;
	description: string;
	type: SettingType;
	options?: string[];
	dependsOn?: string;
	experimental?: boolean;
}
interface SettingsResponse {
	catalog: Descriptor[];
	values: Record<string, unknown>;
	restartRequired: boolean;
	changedKeys: string[];
}

// Same equality the server uses to decide what really changed (lib/admin/settings/routes.ts), and it
// has to be: a `string-array` or `json` setting is a fresh object on every edit, so an identity
// comparison would report every one of them as dirty the moment the page loads.
const sameValue = (a: unknown, b: unknown): boolean =>
	JSON.stringify(a) === JSON.stringify(b);

// A setting's label, tagged when it enables a feature implemented from a draft spec — so an
// operator sees that before turning it on. Shared by both places a label is rendered (the feature
// toggles and the accordion headers), so one of them cannot quietly stop showing it.
function settingLabel(d: Descriptor) {
	if (!d.experimental) return d.label;
	return (
		<span>
			{d.label} <Tag color="orange">experimental</Tag>
		</span>
	);
}

// The detail groups whose primary is currently enabled — used to seed which
// accordion panels start expanded after a load/save.
function enabledDetailGroups(
	catalog: Descriptor[],
	values: Record<string, unknown>
): string[] {
	const detailGroups = new Set(
		catalog.filter((d) => d.dependsOn).map((d) => d.group)
	);
	return [...detailGroups].filter((g) => {
		const primary = catalog.find((d) => d.group === g && !d.dependsOn);
		return primary ? values[primary.key] === true : false;
	});
}

interface SmtpView {
	host: string;
	port: number;
	secure: boolean;
	username: string;
	password: string;
	fromName: string;
	fromEmail: string;
	configured: boolean;
}

// Runtime SMTP transport used for verification emails. Separate from the boot-only
// feature settings above: changes take effect immediately (no restart). The password is
// write-only — the API returns a mask and accepts the mask back to mean "unchanged".
function SmtpSettingsCard() {
	const [form] = Form.useForm<SmtpView>();
	const [loading, setLoading] = useState(true);
	const [saving, setSaving] = useState(false);

	async function load() {
		setLoading(true);
		try {
			const res = await fetch('/admin/api/settings/smtp');
			if (res.ok) form.setFieldsValue((await res.json()) as SmtpView);
		} finally {
			setLoading(false);
		}
	}
	useEffect(() => {
		load();
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, []);

	async function save(values: SmtpView) {
		setSaving(true);
		try {
			const res = await fetch('/admin/api/settings/smtp', {
				method: 'PUT',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify(values)
			});
			const body = (await res.json().catch(() => null)) as
				(SmtpView & { message?: string }) | null;
			if (!res.ok) {
				message.error(body?.message || 'failed to save SMTP settings');
				return;
			}
			if (body) form.setFieldsValue(body);
			message.success('SMTP settings saved');
		} finally {
			setSaving(false);
		}
	}

	return (
		<Card
			title="Email (SMTP)"
			size="small"
			style={{ marginBottom: 16 }}
			loading={loading}
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
			<Form<SmtpView>
				form={form}
				layout="vertical"
				onFinish={save}
			>
				<Form.Item
					name="host"
					label="Host"
					rules={[{ required: true }]}
				>
					<Input placeholder="smtp.example.com" />
				</Form.Item>
				<Form.Item
					name="port"
					label="Port"
					rules={[{ required: true }]}
				>
					{/*
					 * `InputNumber`, not `<Input type="number">`: the latter is still a text input and
					 * submits "587" as a string, which the body schema refuses. See the note on `port` in
					 * lib/admin/settings/smtp/schema.ts.
					 */}
					<InputNumber
						min={1}
						max={65535}
						step={1}
						placeholder="587"
						style={{ width: '100%' }}
					/>
				</Form.Item>
				<Form.Item
					name="secure"
					label="Use TLS on connect"
					valuePropName="checked"
				>
					<Switch />
				</Form.Item>
				<Form.Item
					name="username"
					label="Username"
				>
					<Input autoComplete="off" />
				</Form.Item>
				<Form.Item
					name="password"
					label="Password"
					help="Leave the masked value to keep the stored password."
				>
					<Input.Password autoComplete="new-password" />
				</Form.Item>
				<Form.Item
					name="fromName"
					label="Sender name"
				>
					<Input placeholder="Example" />
				</Form.Item>
				<Form.Item
					name="fromEmail"
					label="Sender email"
					rules={[{ required: true, type: 'email' }]}
				>
					<Input placeholder="no-reply@example.com" />
				</Form.Item>
			</Form>
		</Card>
	);
}

export function Settings() {
	const [catalog, setCatalog] = useState<Descriptor[]>([]);
	const [values, setValues] = useState<Record<string, unknown>>({});
	// What the server last told us it holds. Save submits the difference against this, so one edited
	// toggle reaches the API — and the audit trail — as one field rather than the whole catalogue.
	const [baseline, setBaseline] = useState<Record<string, unknown>>({});
	const [restartRequired, setRestartRequired] = useState(false);
	const [changedKeys, setChangedKeys] = useState<string[]>([]);
	const [loading, setLoading] = useState(true);
	const [saving, setSaving] = useState(false);
	const [openGroups, setOpenGroups] = useState<string[]>([]);

	function apply(body: SettingsResponse) {
		setCatalog(body.catalog);
		setValues(body.values);
		setBaseline(body.values);
		setRestartRequired(body.restartRequired);
		setChangedKeys(body.changedKeys);
		setOpenGroups(enabledDetailGroups(body.catalog, body.values));
	}

	async function load() {
		setLoading(true);
		try {
			const res = await fetch('/admin/api/settings');
			if (res.ok) apply((await res.json()) as SettingsResponse);
		} finally {
			setLoading(false);
		}
	}
	useEffect(() => {
		load();
	}, []);

	// The keys this page has actually edited since the last load or save.
	const dirtyKeys = useMemo(
		() => Object.keys(values).filter((k) => !sameValue(values[k], baseline[k])),
		[values, baseline]
	);

	async function save() {
		if (dirtyKeys.length === 0) {
			message.info('no changes to save');
			return;
		}
		setSaving(true);
		try {
			const changes: Record<string, unknown> = {};
			for (const key of dirtyKeys) changes[key] = values[key];
			const res = await fetch('/admin/api/settings', {
				method: 'PUT',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify(changes)
			});
			const body = (await res.json().catch(() => null)) as
				(SettingsResponse & { message?: string }) | null;
			if (!res.ok) {
				message.error(body?.message || 'failed to save settings');
				return;
			}
			if (body) apply(body);
			message.success('settings saved');
		} finally {
			setSaving(false);
		}
	}

	function setValue(key: string, value: unknown) {
		setValues((prev) => ({ ...prev, [key]: value }));
	}

	// Toggle a primary feature flag. On disable, cascade-reset its boolean detail
	// dependents to false (so a hidden-but-true dependent can't trip the server's
	// merged-config validation on Save), and collapse its panel; on enable, expand it.
	function onToggleFeature(primary: Descriptor, checked: boolean) {
		setValues((prev) => {
			const next = { ...prev, [primary.key]: checked };
			if (!checked) {
				for (const d of catalog) {
					if (d.dependsOn === primary.key && d.type === 'boolean') {
						next[d.key] = false;
					}
				}
			}
			return next;
		});
		setOpenGroups((prev) =>
			checked
				? prev.includes(primary.group)
					? prev
					: [...prev, primary.group]
				: prev.filter((g) => g !== primary.group)
		);
	}

	// Section partition, derived from the catalog.
	const detailGroups = useMemo(
		() => new Set(catalog.filter((d) => d.dependsOn).map((d) => d.group)),
		[catalog]
	);
	const toggleRows = useMemo(
		() =>
			catalog.filter(
				(d) =>
					!d.dependsOn && d.type === 'boolean' && !detailGroups.has(d.group)
			),
		[catalog, detailGroups]
	);
	const accordion = useMemo(() => {
		const order: string[] = [];
		for (const d of catalog) {
			if (detailGroups.has(d.group) && !order.includes(d.group)) {
				order.push(d.group);
			}
		}
		return order.map((group) => ({
			group,
			primary: catalog.find(
				(d) => d.group === group && !d.dependsOn
			) as Descriptor,
			details: catalog.filter((d) => d.group === group && d.dependsOn)
		}));
	}, [catalog, detailGroups]);
	const otherGroups = useMemo(() => {
		const rest = catalog.filter(
			(d) => !d.dependsOn && d.type !== 'boolean' && !detailGroups.has(d.group)
		);
		const order: string[] = [];
		for (const d of rest) if (!order.includes(d.group)) order.push(d.group);
		return order.map((group) => ({
			group,
			items: rest.filter((d) => d.group === group)
		}));
	}, [catalog, detailGroups]);

	function control(d: Descriptor) {
		const value = values[d.key];
		if (d.type === 'boolean') {
			return (
				<Switch
					checked={value === true}
					onChange={(checked) => setValue(d.key, checked)}
				/>
			);
		}
		if (d.type === 'number') {
			return (
				<InputNumber
					style={{ maxWidth: 200 }}
					min={1}
					step={1}
					value={value as number}
					onChange={(v) => setValue(d.key, v)}
				/>
			);
		}
		if (d.type === 'enum') {
			return (
				<Select
					style={{ minWidth: 220 }}
					value={value as string}
					options={(d.options ?? []).map((o) => ({ label: o, value: o }))}
					onChange={(v) => setValue(d.key, v)}
				/>
			);
		}
		if (d.type === 'string-array') {
			return (
				<Select
					mode={d.options ? 'multiple' : 'tags'}
					style={{ minWidth: 320 }}
					value={(value as string[]) ?? []}
					options={(d.options ?? []).map((o) => ({ label: o, value: o }))}
					onChange={(v) => setValue(d.key, v)}
				/>
			);
		}
		if (d.type === 'json') {
			/*
			 * Edited as text and parsed on change, keeping the last valid parse as the value. The server
			 * is the authority on whether the structure is acceptable — a bespoke form per structured
			 * setting would restate rules that already live in validateConfiguration.
			 */
			return (
				<JsonField
					value={value}
					onChange={(parsed) => setValue(d.key, parsed)}
				/>
			);
		}
		return (
			<Input
				style={{ maxWidth: 320 }}
				value={(value as string) ?? ''}
				onChange={(e) => setValue(d.key, e.target.value)}
			/>
		);
	}

	function field(d: Descriptor) {
		return (
			<Form.Item
				key={d.key}
				label={settingLabel(d)}
				help={d.description}
				style={{ marginBottom: 16 }}
			>
				{control(d)}
			</Form.Item>
		);
	}

	return (
		<>
			<div
				style={{
					display: 'flex',
					justifyContent: 'space-between',
					alignItems: 'center',
					marginBottom: 16
				}}
			>
				<Typography.Title
					level={4}
					style={{ margin: 0 }}
				>
					Server settings
				</Typography.Title>
				<Button
					type="primary"
					loading={saving}
					disabled={dirtyKeys.length === 0}
					onClick={save}
				>
					Save
				</Button>
			</div>
			{restartRequired && (
				<Alert
					type="warning"
					showIcon
					style={{ marginBottom: 16 }}
					message="Restart required to apply"
					description={`Saved changes take effect after a server restart: ${changedKeys.join(', ')}`}
				/>
			)}

			<Card
				title="Features"
				size="small"
				style={{ marginBottom: 16 }}
				loading={loading}
			>
				<Form layout="vertical">{toggleRows.map(field)}</Form>
			</Card>

			<Collapse
				style={{ marginBottom: 16 }}
				collapsible="icon"
				activeKey={openGroups}
				onChange={(keys) =>
					setOpenGroups(
						Array.isArray(keys) ? (keys as string[]) : [keys as string]
					)
				}
				items={accordion.map(({ group, primary, details }) => {
					const on = values[primary.key] === true;
					return {
						key: group,
						label: (
							<div>
								<div>{settingLabel(primary)}</div>
								<Typography.Text
									type="secondary"
									style={{ fontSize: 12 }}
								>
									{primary.description}
								</Typography.Text>
							</div>
						),
						extra: (
							<Switch
								checked={on}
								onChange={(checked) => onToggleFeature(primary, checked)}
							/>
						),
						children: on ? (
							<Form layout="vertical">
								{details
									.filter((d) => values[d.dependsOn as string] === true)
									.map(field)}
							</Form>
						) : (
							<Typography.Text type="secondary">
								Enable this feature to configure its options.
							</Typography.Text>
						)
					};
				})}
			/>

			{otherGroups.map(({ group, items }) => (
				<Card
					key={group}
					title={group}
					size="small"
					style={{ marginBottom: 16 }}
					loading={loading}
				>
					<Form layout="vertical">{items.map(field)}</Form>
				</Card>
			))}

			<SmtpSettingsCard />
		</>
	);
}
