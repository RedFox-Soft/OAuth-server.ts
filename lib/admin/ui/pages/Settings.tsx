import { useEffect, useMemo, useState } from 'react';
import { Alert, Badge, Card, Input, Menu, Typography, message } from 'antd';
import { SearchOutlined } from '@ant-design/icons';
import {
	cascadeOff,
	dirtyKeys,
	domainsWithDirty,
	groupsFor,
	matches,
	pendingChanges,
	type Descriptor,
	type DomainMeta,
	type SettingDomain,
	type SettingsResponse,
	type Values
} from '../settings/model.js';
import { GroupCard } from '../settings/GroupCard.js';
import { SaveBar } from '../settings/SaveBar.js';
import { SmtpCard } from '../settings/SmtpCard.js';
import { SentryCard } from '../settings/SentryCard.js';

/*
 * The server settings console.
 *
 * One pane at a time, one card per catalog group, one save control. What it replaces put every
 * setting on a single scroll in three different containers — a flat card of fourteen switches, a
 * thirteen-panel accordion, and two more cards — with which container a setting landed in decided by
 * whether it happened to have sub-settings rather than by what it did, and with three save models
 * competing on the same page.
 *
 * The panes and the cards are both read from the catalog (`domain` and `group`), so this file holds
 * no list of settings to fall out of step with the one the server validates against.
 */
export function Settings() {
	const [catalog, setCatalog] = useState<Descriptor[]>([]);
	const [domains, setDomains] = useState<DomainMeta[]>([]);
	const [values, setValues] = useState<Values>({});
	/*
	 * What the server last told us it holds. Save submits the difference against this, so one edited
	 * toggle reaches the API — and the audit trail — as one field rather than the whole catalogue.
	 */
	const [baseline, setBaseline] = useState<Values>({});
	const [restartRequired, setRestartRequired] = useState(false);
	const [changedKeys, setChangedKeys] = useState<string[]>([]);
	const [loading, setLoading] = useState(true);
	const [saving, setSaving] = useState(false);
	const [pane, setPane] = useState<SettingDomain | null>(null);
	const [query, setQuery] = useState('');

	function apply(body: SettingsResponse) {
		setCatalog(body.catalog);
		setDomains(body.domains);
		setValues(body.values);
		setBaseline(body.values);
		setRestartRequired(body.restartRequired);
		setChangedKeys(body.changedKeys);
		setPane((current) => current ?? body.domains[0]?.id ?? null);
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

	const dirty = useMemo(() => dirtyKeys(values, baseline), [values, baseline]);
	const dirtySet = useMemo(() => new Set(dirty), [dirty]);
	const changes = useMemo(
		() => pendingChanges(catalog, values, baseline),
		[catalog, values, baseline]
	);
	const dirtyPanes = useMemo(
		() => domainsWithDirty(catalog, dirty),
		[catalog, dirty]
	);

	/*
	 * Leaving with edits in hand used to lose them without a word — the shell swaps the page on a
	 * click and nothing asked. This catches the browser-level exits; the in-app ones are caught by
	 * the same dirty count being visible in the bar at the foot of the page.
	 */
	useEffect(() => {
		if (dirty.length === 0) return;
		const warn = (e: BeforeUnloadEvent) => e.preventDefault();
		window.addEventListener('beforeunload', warn);
		return () => window.removeEventListener('beforeunload', warn);
	}, [dirty.length]);

	function setValue(key: string, value: unknown) {
		setValues((prev) => ({ ...prev, [key]: value }));
	}

	/*
	 * Turning a feature off clears its boolean dependents, so the merged configuration the server
	 * validates stays saveable. Unlike before, the rows stay on screen while it happens — the reset is
	 * something the operator watches rather than something they discover on the next load.
	 */
	function togglePrimaryOff(primary: Descriptor) {
		setValues((prev) => cascadeOff(catalog, prev, primary.key));
	}

	async function save() {
		if (dirty.length === 0) return;
		setSaving(true);
		try {
			const body: Values = {};
			for (const key of dirty) body[key] = values[key];
			const res = await fetch('/admin/api/settings', {
				method: 'PUT',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify(body)
			});
			const parsed = (await res.json().catch(() => null)) as
				(SettingsResponse & { message?: string }) | null;
			if (!res.ok) {
				message.error(parsed?.message || 'failed to save settings');
				return;
			}
			if (parsed) apply(parsed);
			message.success('settings saved');
		} finally {
			setSaving(false);
		}
	}

	/*
	 * Search spans every pane, because an operator looking for a setting does not know which pane it
	 * is on — that being the reason to search rather than navigate. While a query is active the
	 * sub-nav selection is ignored and the matching cards from all panes are shown together.
	 */
	const searching = query.trim() !== '';
	const visible = useMemo(
		() => (searching ? catalog.filter((d) => matches(d, query)) : catalog),
		[catalog, query, searching]
	);
	const panesToRender = useMemo(() => {
		if (!searching) return pane ? [pane] : [];
		return domains
			.map((d) => d.id)
			.filter((id) => {
				return visible.some((d) => d.domain === id);
			});
	}, [searching, pane, domains, visible]);

	const cards = panesToRender.flatMap((id) =>
		groupsFor(visible, id).map((view) => ({ id, view }))
	);

	return (
		<>
			<div
				style={{
					display: 'flex',
					justifyContent: 'space-between',
					alignItems: 'center',
					gap: 16,
					flexWrap: 'wrap',
					marginBottom: 16
				}}
			>
				<Typography.Title
					level={4}
					style={{ margin: 0 }}
				>
					Server settings
				</Typography.Title>
				<Input
					allowClear
					prefix={<SearchOutlined />}
					placeholder="Search all settings"
					style={{ maxWidth: 320 }}
					value={query}
					onChange={(e) => setQuery(e.target.value)}
				/>
			</div>

			{restartRequired && (
				<Alert
					type="warning"
					showIcon
					style={{ marginBottom: 16 }}
					message="Saved changes are waiting for a restart"
					description={`These settings are stored but not yet in force: ${changedKeys.join(', ')}`}
				/>
			)}

			<div style={{ display: 'flex', gap: 16, alignItems: 'flex-start' }}>
				<Card
					size="small"
					style={{ flex: '0 0 210px', position: 'sticky', top: 0 }}
					styles={{ body: { padding: 0 } }}
					loading={loading}
				>
					<Menu
						mode="inline"
						style={{ borderInlineEnd: 'none' }}
						selectedKeys={searching ? [] : pane ? [pane] : []}
						onClick={({ key }) => {
							setQuery('');
							setPane(key as SettingDomain);
						}}
						items={domains.map((d) => ({
							key: d.id,
							label: dirtyPanes.has(d.id) ? (
								<Badge
									dot
									offset={[6, 0]}
								>
									{d.label}
								</Badge>
							) : (
								d.label
							)
						}))}
					/>
				</Card>

				<div style={{ flex: 1, minWidth: 0 }}>
					{searching ? (
						<Typography.Paragraph type="secondary">
							{cards.length === 0
								? `Nothing matches “${query}”.`
								: `Showing settings matching “${query}” from every section.`}
						</Typography.Paragraph>
					) : (
						<Typography.Paragraph type="secondary">
							{domains.find((d) => d.id === pane)?.blurb}
						</Typography.Paragraph>
					)}

					{cards.map(({ id, view }) => (
						<GroupCard
							key={`${id}:${view.group}`}
							view={view}
							values={values}
							dirty={dirtySet}
							onChange={setValue}
							onTogglePrimaryOff={togglePrimaryOff}
						/>
					))}

					{/*
					 * The two runtime surfaces, each on the pane it belongs to and each saved by its own
					 * button, because each is its own endpoint that applies immediately. The Sentry
					 * credential sits beside the Error Store card rather than nested inside it: it is the
					 * prerequisite for the reporting toggle there, so it has to be reachable without first
					 * opening anything.
					 */}
					{!searching && pane === 'diagnostics' && <SentryCard />}
					{!searching && pane === 'integrations' && <SmtpCard />}

					<SaveBar
						changes={changes}
						saving={saving}
						onSave={save}
						onDiscard={() => setValues(baseline)}
					/>
				</div>
			</div>
		</>
	);
}
