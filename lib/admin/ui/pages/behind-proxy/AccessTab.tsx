import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
	Alert,
	Button,
	Card,
	Checkbox,
	Drawer,
	Flex,
	Input,
	Select,
	Space,
	Tag,
	Typography
} from 'antd';
import { DeleteOutlined, PlusOutlined } from '@ant-design/icons';
import { request } from '../../frame/request.js';
import { useFeedback } from '../../frame/feedback.js';
import { useConfirm } from '../../frame/confirm.js';
import { ACTIONS } from '../../frame/actions.js';
import { Link, useLeaveGuard } from '../../frame/router.js';
import { behindProxyHref } from '../../frame/routes.js';
import { ConfirmDestruction } from '../../ConfirmDestruction.js';
import { SaveBar } from '../../settings/SaveBar.js';
import type { Change } from '../../settings/model.js';
import type { GroupView } from '../groups/groupShared.js';
import { usersApi, type EndUser } from '../users/endUser.js';
import { sameHost } from '../../../../behind_proxy/address.js';
import {
	checkAccess,
	personOfView,
	rulesOfView,
	targetOf,
	whoOfView
} from '../../../../behind_proxy/access_check.js';
import {
	APP_ORDER,
	type Condition
} from '../../../../behind_proxy/conditions.js';
import { ConditionsEditor } from './ConditionsEditor.js';
import { conditionText, KIND_LABELS, loosenedText } from './conditionsText.js';
import {
	baseWho,
	widenings,
	withConditions,
	type Decision,
	type PathRule,
	type PlainWho,
	type Widening
} from '../../../../behind_proxy/decide.js';
import {
	addressesProven,
	behindProxyApi,
	hostOfAddress,
	pathText,
	whoText,
	type AppView
} from './appView.js';

interface DraftRule {
	key: string;
	path: string;
	who: PlainWho;
	/* The rule's own conditions (specs/124). */
	conditions: Condition[];
	/* The rule for `/`: always there, never removed, its path not editable. */
	root?: true;
}

type WhoKind = PlainWho['kind'];

const WHO_OPTIONS: { value: WhoKind; label: string }[] = [
	{ value: 'groups', label: 'Members of…' },
	{ value: 'project', label: 'Everyone in the project' },
	{ value: 'public', label: 'Anyone, no sign-in' },
	{ value: 'none', label: 'No one' }
];

const METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'];

const MAX_RULES = 50;

let keys = 0;
function nextKey(): string {
	keys += 1;
	return `rule-${String(keys)}`;
}

/* A path as the decision compares it: no trailing slash, letter case ignored. */
function norm(path: string): string {
	const trimmed = path.trim().replace(/\/+$/, '');
	return (trimmed || '/').toLowerCase();
}

function segments(path: string): string[] {
	return norm(path).split('/').filter(Boolean);
}

/* Parents before their children, siblings by name: the order a tree is read in. */
function byTree(a: DraftRule, b: DraftRule): number {
	const x = segments(a.path);
	const y = segments(b.path);
	for (let i = 0; i < Math.min(x.length, y.length); i++) {
		if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1;
	}
	return x.length - y.length;
}

function covers(parent: string, child: string): boolean {
	const p = norm(parent);
	const c = norm(child);
	if (p === c) return false;
	return p === '/' || c.startsWith(`${p}/`);
}

function draftOf(app: AppView): DraftRule[] {
	return app.rules
		.map((rule) => ({
			key: nextKey(),
			path: rule.path,
			who: whoOfView(rule.who),
			conditions: rule.conditions ?? [],
			...(norm(rule.path) === '/' ? { root: true as const } : {})
		}))
		.sort(byTree);
}

function rulesOf(draft: readonly DraftRule[]): PathRule[] {
	return draft.map((rule) => ({
		path: rule.path.trim(),
		who: withConditions(rule.who, rule.conditions)
	}));
}

function bodyOf(who: PlainWho) {
	return who.kind === 'groups'
		? { kind: 'groups' as const, groups: who.groupIds }
		: who;
}

/* What is wrong with the draft before the server is asked, in the words a person fixes it by; null when nothing. */
function problemOf(draft: readonly DraftRule[]): string | null {
	const seen = new Set<string>();
	for (const rule of draft) {
		const path = rule.path.trim();
		if (!path.startsWith('/')) {
			return `A path starts with /: “${path || '(empty)'}”.`;
		}
		if (/[?#*%;\\]/.test(path)) {
			return `${path} must not contain ? # * % ; or a backslash.`;
		}
		if (seen.has(norm(path))) return `${path} has more than one rule.`;
		seen.add(norm(path));
		if (rule.who.kind === 'groups' && rule.who.groupIds.length === 0) {
			return `Choose at least one group for ${path}, or another option.`;
		}
	}
	return null;
}

/*
 * Whether the change makes the root public or opens a whole subtree to anyone (FR-036): asked for with the word,
 * not just a question, because it opens an unbounded number of pages to people nobody can name.
 */
function makesPublic(
	before: readonly PathRule[],
	after: readonly PathRule[]
): boolean {
	return after.some((rule) => {
		if (rule.who.kind !== 'public') return false;
		const prior = before.find((b) => norm(b.path) === norm(rule.path))?.who;
		if (norm(rule.path) === '/' && prior?.kind !== 'public') return true;
		return rule.who.subtree && !(prior?.kind === 'public' && prior.subtree);
	});
}

const OUTCOMES: Record<Decision['outcome'], { color: string; label: string }> =
	{
		allow: { color: 'success', label: 'Allowed' },
		sign_in: { color: 'processing', label: 'Signs in first' },
		deny: { color: 'error', label: 'Denied' }
	};

/*
 * Who may open which path of the app, as a tree (specs/122 FR-035): a path's rule under the rule it narrows, the
 * longest match deciding. One form under one save bar; a save that lets more people in anywhere asks first and says
 * where, and one that narrows is saved at once (FR-036). Below it, the access check runs the shared decision on the
 * saved rules and on these edits (FR-037).
 */
export function AccessTab({
	bucketId,
	app,
	groups,
	writable,
	onChanged
}: {
	bucketId: string;
	app: AppView;
	groups: GroupView[];
	writable: boolean;
	onChanged: (app: AppView) => void;
}) {
	const feedback = useFeedback();
	const confirm = useConfirm();
	const host = hostOfAddress(app.address);
	const baseline = useMemo(() => draftOf(app), [app]);
	const [draft, setDraft] = useState<DraftRule[]>(baseline);
	const [saving, setSaving] = useState(false);
	const [refusal, setRefusal] = useState<string | null>(null);
	const [publicLines, setPublicLines] = useState<string[] | null>(null);
	const [zone, setZone] = useState<string | null>(app.timeZone ?? null);
	const [editing, setEditing] = useState<string | null>(null);

	const known = useMemo(
		() => new Map(groups.map((group) => [group.id, group.displayName])),
		[groups]
	);
	const nameOf = useCallback((id: string) => known.get(id) ?? null, [known]);

	const changes: Change[] = useMemo(() => {
		const said = (rule: DraftRule | undefined) =>
			rule
				? [
						whoText(rule.who, nameOf),
						...rule.conditions.map((c) => conditionText(c, nameOf))
					].join('; ')
				: undefined;
		const before = new Map(baseline.map((r) => [norm(r.path), r]));
		const after = new Map(draft.map((r) => [norm(r.path), r]));
		const paths = [...new Set([...before.keys(), ...after.keys()])];
		const ruleChanges: Change[] = paths
			.filter((path) => {
				const a = before.get(path);
				const b = after.get(path);
				return (
					JSON.stringify(a ? [a.who, a.conditions] : null) !==
					JSON.stringify(b ? [b.who, b.conditions] : null)
				);
			})
			.map((path) => ({
				key: path,
				label: path,
				group: 'rules',
				from: said(before.get(path)),
				to: after.has(path) ? (said(after.get(path)) ?? '') : 'removed'
			}));
		if ((app.timeZone ?? null) !== zone) {
			ruleChanges.push({
				key: 'timeZone',
				label: 'Time zone',
				group: 'rules',
				from: app.timeZone ?? 'none',
				to: zone ?? 'none'
			});
		}
		return ruleChanges;
	}, [baseline, draft, nameOf, app.timeZone, zone]);
	const dirty = changes.length > 0;
	useLeaveGuard(dirty, changes.length);

	function update(key: string, change: Partial<DraftRule>) {
		setRefusal(null);
		setDraft((current) =>
			current.map((rule) => (rule.key === key ? { ...rule, ...change } : rule))
		);
	}

	function setKind(rule: DraftRule, kind: WhoKind) {
		const who: PlainWho =
			kind === 'groups'
				? {
						kind,
						groupIds: rule.who.kind === 'groups' ? rule.who.groupIds : []
					}
				: kind === 'public'
					? { kind, subtree: false }
					: { kind };
		update(rule.key, { who });
	}

	function addPath() {
		setRefusal(null);
		setDraft((current) => [
			...current,
			{
				key: nextKey(),
				path: '',
				who: { kind: 'groups', groupIds: [] },
				conditions: []
			}
		]);
	}

	function remove(key: string) {
		setRefusal(null);
		setDraft((current) => current.filter((rule) => rule.key !== key));
	}

	function wideningLine(w: Widening): string {
		const where = w.path.endsWith('/*')
			? w.path === '/*'
				? 'Everything'
				: `${w.path.slice(0, -2)} and below`
			: w.path;
		const parts: string[] = [];
		/* "Who" alone: a rule whose conditions changed is still the same "who", and saying so twice says nothing. */
		const fromWho = w.from && baseWho(w.from);
		const toWho = w.to && baseWho(w.to);
		if (JSON.stringify(fromWho) !== JSON.stringify(toWho)) {
			parts.push(`${whoText(w.from, nameOf)} → ${whoText(w.to, nameOf)}`);
		}
		for (const loosened of w.loosened ?? []) {
			parts.push(loosenedText(loosened, nameOf));
		}
		return `${where}: ${parts.join('; ')}`;
	}

	async function put() {
		setSaving(true);
		try {
			const result = await request<AppView>(
				'PATCH',
				behindProxyApi(bucketId, app.id),
				{
					rules: draft.map((rule) => ({
						path: rule.path.trim(),
						who: bodyOf(rule.who),
						...(rule.conditions.length > 0
							? { conditions: rule.conditions }
							: {})
					})),
					...((app.timeZone ?? null) !== zone ? { timeZone: zone } : {})
				}
			);
			if (!result.ok) {
				if (result.status >= 500) feedback.failed(result);
				else setRefusal(result.error.message);
				return;
			}
			feedback.done(`Access to ${host} saved.`);
			setDraft(draftOf(result.data));
			onChanged(result.data);
		} finally {
			setSaving(false);
		}
	}

	async function save() {
		const problem = problemOf(draft);
		if (problem) {
			setRefusal(problem);
			return;
		}
		const before = rulesOfView(app.rules);
		const after = rulesOf(draft);
		const found = widenings(before, after, {
			before: app.timeZone ?? null,
			after: zone
		});
		if (found.length === 0) {
			await put();
			return;
		}
		const lines = found.map(wideningLine);
		if (makesPublic(before, after)) {
			setPublicLines(lines);
			return;
		}
		if (
			await confirm('behindProxy.rules.widen', {
				target: host,
				consequences: lines
			})
		) {
			await put();
		}
	}

	/* The conditions of every path above a rule, which apply to it too (specs/124 FR-003). */
	function inheritedOf(rule: DraftRule): { from: string; text: string }[] {
		return draft
			.filter(
				(other) =>
					other.key !== rule.key &&
					other.path.trim() !== '' &&
					covers(other.path, rule.path)
			)
			.sort((a, b) => norm(a.path).length - norm(b.path).length)
			.flatMap((other) =>
				other.conditions.map((condition) => ({
					from: norm(other.path),
					text: conditionText(condition, nameOf)
				}))
			);
	}

	const editingRule = draft.find((rule) => rule.key === editing) ?? null;

	const rows = draft.map((rule) => {
		const isRoot = rule.root === true;
		const inherited = inheritedOf(rule);
		const conditionable =
			rule.who.kind === 'groups' || rule.who.kind === 'project';
		const depth = draft.filter(
			(other) =>
				other.key !== rule.key &&
				other.path.trim() !== '' &&
				covers(other.path, rule.path)
		).length;
		const who = rule.who;
		return (
			<Flex
				key={rule.key}
				vertical
				gap={6}
				style={{
					paddingLeft: depth * 24,
					paddingBlock: 8,
					borderBottom: '1px solid var(--ant-color-split, rgba(5,5,5,0.06))'
				}}
			>
				<Flex
					gap={8}
					wrap
					align="center"
				>
					<div style={{ width: 260, maxWidth: '100%' }}>
						{isRoot ? (
							<Typography.Text strong>/ (everything)</Typography.Text>
						) : (
							<Space.Compact style={{ width: '100%' }}>
								<Input
									aria-label="Path"
									placeholder="/admin"
									value={rule.path}
									disabled={!writable}
									onChange={(e) => update(rule.key, { path: e.target.value })}
									onBlur={() =>
										setDraft((current) => [...current].sort(byTree))
									}
								/>
							</Space.Compact>
						)}
						{!isRoot && rule.path.trim() !== '' && (
							<Typography.Text
								type="secondary"
								style={{ fontSize: 12 }}
							>
								{who.kind === 'public' && !who.subtree
									? 'Only this exact path'
									: pathText(rule.path.trim(), who)}
							</Typography.Text>
						)}
					</div>
					<Select<WhoKind>
						aria-label={`Who can open ${rule.path || 'this path'}`}
						style={{ width: 220 }}
						value={who.kind}
						disabled={!writable}
						options={WHO_OPTIONS}
						onChange={(kind) => setKind(rule, kind)}
					/>
					{who.kind === 'groups' && (
						<Select
							mode="multiple"
							aria-label="Groups"
							placeholder="Choose groups"
							style={{ minWidth: 240, flex: 1 }}
							value={who.groupIds}
							disabled={!writable}
							showSearch={{ optionFilterProp: 'label' }}
							options={groups.map((group) => ({
								value: group.id,
								label: group.displayName
							}))}
							onChange={(groupIds: string[]) =>
								update(rule.key, { who: { kind: 'groups', groupIds } })
							}
							tagRender={({ value, label, closable, onClose }) => (
								<Tag
									color={known.has(String(value)) ? undefined : 'red'}
									closable={closable}
									onClose={onClose}
								>
									{known.has(String(value)) ? label : 'Deleted group'}
								</Tag>
							)}
						/>
					)}
					{who.kind === 'public' && (
						<>
							<Tag>Public</Tag>
							<Checkbox
								checked={who.subtree}
								disabled={!writable}
								onChange={(e) =>
									update(rule.key, {
										who: { kind: 'public', subtree: e.target.checked }
									})
								}
							>
								and everything under it
							</Checkbox>
						</>
					)}
					{!isRoot && writable && (
						<Button
							aria-label={`Remove the rule for ${rule.path || 'this path'}`}
							icon={<DeleteOutlined />}
							onClick={() => remove(rule.key)}
						/>
					)}
				</Flex>
				{conditionable ? (
					<Flex
						gap={8}
						wrap
						align="baseline"
					>
						{inherited.length + rule.conditions.length === 0 ? (
							<Typography.Text type="secondary">No conditions.</Typography.Text>
						) : (
							<Typography.Text>
								Only if:{' '}
								{inherited.map((line, i) => (
									<Typography.Text
										key={`i${String(i)}`}
										type="secondary"
									>
										{line.text} (from {line.from}){' · '}
									</Typography.Text>
								))}
								{rule.conditions
									.map((condition) => conditionText(condition, nameOf))
									.join(' · ')}
							</Typography.Text>
						)}
						{writable && (
							<Button
								size="small"
								type="link"
								onClick={() => setEditing(rule.key)}
							>
								Edit conditions
							</Button>
						)}
					</Flex>
				) : (
					who.kind === 'public' && (
						<Typography.Text
							type="secondary"
							style={{ fontSize: 12 }}
						>
							Conditions don&apos;t apply to public paths.
						</Typography.Text>
					)
				)}
				{who.kind === 'project' && app.signUpsOpen && (
					<Alert
						type="warning"
						showIcon
						title="Sign-ups are open: anyone can create an account and get in."
					/>
				)}
				{who.kind === 'public' && (
					<Typography.Text
						type={who.subtree ? 'warning' : 'secondary'}
						style={{ fontSize: 12 }}
					>
						{who.subtree
							? `Anyone can read every page under ${rule.path.trim() || 'this path'} without signing in.`
							: 'Only reading (GET and HEAD) is open; anything else is decided by the rule above.'}
					</Typography.Text>
				)}
			</Flex>
		);
	});

	return (
		<Flex
			vertical
			gap={16}
		>
			{refusal && (
				<Alert
					type="error"
					showIcon
					title={refusal}
				/>
			)}
			<Card
				size="small"
				title="Who can open it"
				extra={
					<Typography.Text type="secondary">
						The longest matching path decides.
					</Typography.Text>
				}
			>
				<Flex vertical>
					{rows}
					{writable && (
						<div style={{ paddingTop: 12 }}>
							<Button
								icon={<PlusOutlined />}
								disabled={draft.length >= MAX_RULES}
								onClick={addPath}
							>
								Add path
							</Button>
						</div>
					)}
				</Flex>
			</Card>
			<Typography.Text type="secondary">
				The FoxAuth console is never behind these conditions, so a rule here
				cannot lock you out of it.
			</Typography.Text>
			<AccessCheck
				bucketId={bucketId}
				app={app}
				draft={dirty ? rulesOf(draft) : null}
				zone={zone}
				nameOf={nameOf}
			/>
			<Drawer
				open={editingRule !== null}
				size="large"
				title={
					editingRule
						? `Conditions for ${editingRule.root ? '/ (everything)' : `${editingRule.path.trim()} and below`}`
						: 'Conditions'
				}
				onClose={() => setEditing(null)}
				extra={
					<Button
						type="primary"
						onClick={() => setEditing(null)}
					>
						Done
					</Button>
				}
			>
				{editingRule && (
					<ConditionsEditor
						conditions={editingRule.conditions}
						kinds={APP_ORDER}
						inherited={inheritedOf(editingRule)}
						timeZone={zone}
						onTimeZone={(next) => {
							setRefusal(null);
							setZone(next);
						}}
						countUrl={`/admin/api/projects/${encodeURIComponent(bucketId)}/attribute-matches`}
						disabled={!writable}
						unavailable={
							addressesProven(app.addresses)
								? {}
								: {
										network: (
											<>
												{KIND_LABELS.network} is available once your proxy shows
												it passes people&apos;s addresses: finish{' '}
												<Link href={behindProxyHref(bucketId, app.id)}>
													&ldquo;Your proxy passes people&apos;s
													addresses&rdquo; on Connect
												</Link>{' '}
												first.
											</>
										)
									}
						}
						onChange={(conditions) => update(editingRule.key, { conditions })}
					/>
				)}
				<Typography.Text
					type="secondary"
					style={{ display: 'block', marginTop: 16 }}
				>
					Changes here are saved with the page.
				</Typography.Text>
			</Drawer>
			{writable && (
				<SaveBar
					changes={changes}
					saving={saving}
					onSave={() => void save()}
					onDiscard={() => {
						setRefusal(null);
						setDraft(baseline);
					}}
				/>
			)}
			<ConfirmDestruction
				open={publicLines !== null}
				title={`Open ${host} to anyone?`}
				warning="Anyone, without signing in, can then read these pages"
				consequences={publicLines ?? []}
				word={ACTIONS['behindProxy.rules.public'].word}
				okText="Save changes"
				busy={saving}
				onCancel={() => setPublicLines(null)}
				onConfirm={() => {
					setPublicLines(null);
					void put();
				}}
			/>
		</Flex>
	);
}

interface PersonOption {
	id: string;
	email: string;
	view: EndUser;
}

/*
 * The access check (FR-037): an address and a person in; the path as it was understood, the outcome now and after
 * save, the rule that decided and why, out. Built on the same decision the proxy's check runs, from what the admin
 * routes say about the person, so it cannot answer differently from the proxy (FR-011).
 */
const RESULT_MARKS: Record<string, { mark: string; color: string }> = {
	pass: { mark: '✓', color: 'success' },
	fail: { mark: '✗', color: 'error' },
	unknown: { mark: '?', color: 'default' }
};

const SIGNED_IN_OPTIONS = [
	{ value: 0, label: 'just now' },
	{ value: 10, label: '10 min ago' },
	{ value: 30, label: '30 min ago' },
	{ value: 120, label: '2 h ago' },
	{ value: 720, label: '12 h ago' }
];

/* A `datetime-local` value, read as the browser's own clock; empty means now. */
function momentOf(value: string): number {
	if (value === '') return Date.now();
	const at = Date.parse(value);
	return Number.isNaN(at) ? Date.now() : at;
}

function AccessCheck({
	bucketId,
	app,
	draft,
	zone,
	nameOf
}: {
	bucketId: string;
	app: AppView;
	/* The edited rules, or null when nothing is edited. */
	draft: PathRule[] | null;
	/* The zone the edited rules are read in. */
	zone: string | null;
	nameOf: (id: string) => string | null;
}) {
	const [address, setAddress] = useState('');
	const [from, setFrom] = useState('');
	const [moment, setMoment] = useState('');
	const [signedInAgo, setSignedInAgo] = useState(0);
	const [method, setMethod] = useState('GET');
	const [personId, setPersonId] = useState('');
	const [people, setPeople] = useState<PersonOption[]>([]);
	const [chosen, setChosen] = useState<PersonOption | null>(null);
	const searchSeq = useRef(0);

	const search = useCallback(
		(q: string) => {
			searchSeq.current += 1;
			const seq = searchSeq.current;
			const query = new URLSearchParams({ count: '10' });
			if (q.trim()) query.set('q', q.trim());
			void request<{ users: EndUser[] }>(
				'GET',
				`${usersApi(bucketId)}?${query.toString()}`
			).then((result) => {
				if (seq !== searchSeq.current || !result.ok) return;
				setPeople(
					result.data.users.map((user) => ({
						id: user._id,
						email: user.email,
						view: user
					}))
				);
			});
		},
		[bucketId]
	);

	useEffect(() => {
		search('');
	}, [search]);

	const at = momentOf(moment);
	const viewed = personOfView(
		chosen
			? {
					active: chosen.view.active,
					lockedLocally: chosen.view.lockedLocally,
					groups: chosen.view.groups,
					profile: chosen.view.profile,
					claims: chosen.view.claims
				}
			: null
	);
	const person = viewed
		? { ...viewed, signedInAt: Math.floor(at / 1000) - signedInAgo * 60 }
		: null;
	const typed = address.trim();
	const target = typed ? targetOf(typed) : null;
	const inputs = {
		method,
		address: typed,
		person,
		from: from.trim() === '' ? null : from.trim(),
		at
	};
	const saved = typed
		? checkAccess({
				...inputs,
				rules: rulesOfView(app.rules),
				timeZone: app.timeZone ?? null
			})
		: null;
	const edited =
		typed && draft
			? checkAccess({ ...inputs, rules: draft, timeZone: zone })
			: null;

	function reasonOf(decision: Decision, rules: readonly PathRule[]): string {
		const who = chosen?.email ?? 'The person';
		const rule = rules.find(
			(r) => norm(r.path) === norm(decision.rule ?? '\u0000')
		);
		const ruleLabel = rule
			? pathText(rule.path, baseWho(rule.who))
			: decision.rule;
		const theirGroups = (chosen?.view.groups ?? []).map(
			(g) => nameOf(g.id) ?? g.displayName
		);
		switch (decision.reason) {
			case 'allowed':
				if (rule?.who.kind === 'groups') {
					const shared = rule.who.groupIds
						.filter((id) => chosen?.view.groups?.some((g) => g.id === id))
						.map((id) => nameOf(id) ?? 'a group');
					return `${who} is in ${shared.join(', ')}.`;
				}
				return `${who} can sign in to this project.`;
			case 'public':
				return 'Anyone may open it without signing in.';
			case 'no_session':
				return 'Nobody is signed in, so the browser is sent to sign in first.';
			case 'not_in_group':
				return `${ruleLabel ?? 'The rule'} lets in ${whoText(rule?.who ?? null, nameOf).replace(/^Members of /, 'members of ')}; ${who} is in ${theirGroups.length ? theirGroups.join(', ') : 'no group'}.`;
			case 'cannot_sign_in':
				return `${who} is deactivated or locked, so this project does not let them sign in.`;
			case 'rule_no_one':
				return rule
					? `${ruleLabel ?? rule.path} lets no one in.`
					: 'No rule covers it: a public rule covers only reading its own path, and nothing above it decides.';
			case 'ambiguous_path':
				return 'The app could read this path differently (an encoded slash or dot, a backslash, a semicolon), so it is refused before any rule.';
			case 'not_from_network':
				return 'The address is not one the conditions let in, so it is refused before anyone signs in.';
			case 'outside_hours':
				return 'It is outside the hours the conditions allow.';
			case 'attribute_mismatch':
				return `${who} does not have the attribute the conditions ask for.`;
			case 'sign_in_again':
				return `${who} signed in longer ago than the path allows, so they are asked to sign in again.`;
			default:
				return decision.reason;
		}
	}

	function verdict(
		label: string,
		decision: Decision,
		rules: readonly PathRule[]
	) {
		const outcome = OUTCOMES[decision.outcome];
		const rule = rules.find(
			(r) => norm(r.path) === norm(decision.rule ?? '\u0000')
		);
		return (
			<Flex
				gap={8}
				wrap
				align="baseline"
			>
				<Typography.Text strong>{label}</Typography.Text>
				<Tag color={outcome.color}>{outcome.label}</Tag>
				{rule && (
					<Typography.Text type="secondary">
						by {pathText(rule.path, baseWho(rule.who))}
					</Typography.Text>
				)}
				<Typography.Text>{reasonOf(decision, rules)}</Typography.Text>
				{(decision.conditions ?? []).length > 0 && (
					<Flex
						vertical
						gap={2}
						style={{ width: '100%', paddingLeft: 16 }}
					>
						{(decision.conditions ?? []).map((judged, i) => {
							const mark = RESULT_MARKS[judged.result];
							return (
								<Typography.Text key={`${String(i)}:${judged.from}`}>
									<Tag color={mark.color}>{mark.mark}</Tag>
									{conditionText(judged.condition, nameOf)}{' '}
									<Typography.Text type="secondary">
										(from {judged.from}
										{judged.result === 'unknown'
											? '; give an input to check it'
											: ''}
										)
									</Typography.Text>
								</Typography.Text>
							);
						})}
					</Flex>
				)}
			</Flex>
		);
	}

	return (
		<Card
			size="small"
			title="Check access"
		>
			<Flex
				vertical
				gap={12}
			>
				<Flex
					gap={8}
					wrap
				>
					<Select
						aria-label="Method"
						style={{ width: 110 }}
						value={method}
						onChange={setMethod}
						options={METHODS.map((m) => ({ value: m, label: m }))}
					/>
					<Input
						aria-label="Address to check"
						style={{ flex: 2, minWidth: 260 }}
						placeholder={`${app.address}/admin/reports`}
						value={address}
						onChange={(e) => setAddress(e.target.value)}
					/>
					<Select
						aria-label="Person"
						showSearch={{ filterOption: false, onSearch: search }}
						style={{ flex: 1, minWidth: 220 }}
						value={personId}
						onChange={(id: string) => {
							setPersonId(id);
							setChosen(people.find((p) => p.id === id) ?? null);
						}}
						options={[
							{ value: '', label: 'Not signed in' },
							...people.map((p) => ({ value: p.id, label: p.email }))
						]}
					/>
				</Flex>
				<Flex
					gap={8}
					wrap
				>
					<Input
						aria-label="Network address of the person"
						style={{ width: 220 }}
						placeholder="From address, e.g. 203.0.113.9"
						value={from}
						onChange={(e) => setFrom(e.target.value)}
					/>
					<Input
						aria-label="At"
						type="datetime-local"
						style={{ width: 220 }}
						value={moment}
						onChange={(e) => setMoment(e.target.value)}
					/>
					<Select
						aria-label="Signed in"
						style={{ width: 160 }}
						value={signedInAgo}
						onChange={setSignedInAgo}
						options={SIGNED_IN_OPTIONS.map((o) => ({
							value: o.value,
							label: `Signed in ${o.label}`
						}))}
					/>
				</Flex>
				{!typed && (
					<Typography.Text type="secondary">
						Paste an address from the browser and choose a person to see whether
						they would get in, now and after you save.
					</Typography.Text>
				)}
				{target?.host && !sameHost(target.host, app.address) && (
					<Typography.Text type="warning">
						{target.host} is not this app&apos;s address; only the path is
						checked.
					</Typography.Text>
				)}
				{saved && (
					<>
						<Typography.Text>
							Checked as{' '}
							{saved.path ? (
								<Typography.Text code>{saved.path}</Typography.Text>
							) : (
								'a path that cannot be read one way only'
							)}
						</Typography.Text>
						{verdict(
							edited ? 'Now:' : 'Result:',
							saved,
							rulesOfView(app.rules)
						)}
						{edited && draft && verdict('After save:', edited, draft)}
					</>
				)}
			</Flex>
		</Card>
	);
}
