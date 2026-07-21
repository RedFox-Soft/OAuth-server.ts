import { useEffect, useMemo, useState } from 'react';
import {
	Alert,
	Button,
	Card,
	Collapse,
	Form,
	Input,
	Select,
	Switch,
	Typography,
	message
} from 'antd';

type SettingType = 'boolean' | 'string' | 'enum' | 'string-array';
interface Descriptor {
	key: string;
	group: string;
	label: string;
	description: string;
	type: SettingType;
	options?: string[];
	dependsOn?: string;
}
interface SettingsResponse {
	catalog: Descriptor[];
	values: Record<string, unknown>;
	restartRequired: boolean;
	changedKeys: string[];
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

export function Settings() {
	const [catalog, setCatalog] = useState<Descriptor[]>([]);
	const [values, setValues] = useState<Record<string, unknown>>({});
	const [restartRequired, setRestartRequired] = useState(false);
	const [changedKeys, setChangedKeys] = useState<string[]>([]);
	const [loading, setLoading] = useState(true);
	const [saving, setSaving] = useState(false);
	const [openGroups, setOpenGroups] = useState<string[]>([]);

	function apply(body: SettingsResponse) {
		setCatalog(body.catalog);
		setValues(body.values);
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

	async function save() {
		setSaving(true);
		try {
			const res = await fetch('/admin/api/settings', {
				method: 'PUT',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify(values)
			});
			const body = (await res.json().catch(() => null)) as
				| (SettingsResponse & { message?: string })
				| null;
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
				(d) => !d.dependsOn && d.type === 'boolean' && !detailGroups.has(d.group)
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
			primary: catalog.find((d) => d.group === group && !d.dependsOn) as Descriptor,
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
				label={d.label}
				help={d.description}
				style={{ marginBottom: 16 }}
			>
				{control(d)}
			</Form.Item>
		);
	}

	return (
		<>
			<div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
				<Typography.Title level={4} style={{ margin: 0 }}>
					Server settings
				</Typography.Title>
				<Button type="primary" loading={saving} onClick={save}>
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

			<Card title="Features" size="small" style={{ marginBottom: 16 }} loading={loading}>
				<Form layout="vertical">{toggleRows.map(field)}</Form>
			</Card>

			<Collapse
				style={{ marginBottom: 16 }}
				collapsible="icon"
				activeKey={openGroups}
				onChange={(keys) =>
					setOpenGroups(Array.isArray(keys) ? (keys as string[]) : [keys as string])
				}
				items={accordion.map(({ group, primary, details }) => {
					const on = values[primary.key] === true;
					return {
						key: group,
						label: (
							<div>
								<div>{primary.label}</div>
								<Typography.Text type="secondary" style={{ fontSize: 12 }}>
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
				<Card key={group} title={group} size="small" style={{ marginBottom: 16 }} loading={loading}>
					<Form layout="vertical">{items.map(field)}</Form>
				</Card>
			))}
		</>
	);
}
