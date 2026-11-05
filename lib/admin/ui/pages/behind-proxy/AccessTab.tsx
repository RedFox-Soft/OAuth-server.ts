import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
	Alert,
	Button,
	Card,
	Checkbox,
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
import { useLeaveGuard } from '../../frame/router.js';
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
	targetOf
} from '../../../../behind_proxy/access_check.js';
import {
	widenings,
	type Decision,
	type PathRule,
	type Who,
	type Widening
} from '../../../../behind_proxy/decide.js';
import {
	behindProxyApi,
	hostOfAddress,
	pathText,
	whoText,
	type AppView
} from './appView.js';

interface DraftRule {
	key: string;
	path: string;
	who: Who;
	/* The rule for `/`: always there, never removed, its path not editable. */
	root?: true;
}

type WhoKind = Who['kind'];

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
	return rulesOfView(app.rules)
		.map((rule) => ({
			key: nextKey(),
			...rule,
			...(norm(rule.path) === '/' ? { root: true as const } : {})
		}))
		.sort(byTree);
}

function rulesOf(draft: readonly DraftRule[]): PathRule[] {
	return draft.map((rule) => ({ path: rule.path.trim(), who: rule.who }));
}

function bodyOf(who: Who) {
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

	const known = useMemo(
		() => new Map(groups.map((group) => [group.id, group.displayName])),
		[groups]
	);
	const nameOf = useCallback((id: string) => known.get(id) ?? null, [known]);

	const changes: Change[] = useMemo(() => {
		const before = new Map(baseline.map((r) => [norm(r.path), r.who]));
		const after = new Map(draft.map((r) => [norm(r.path), r.who]));
		const paths = [...new Set([...before.keys(), ...after.keys()])];
		return paths
			.filter(
				(path) =>
					JSON.stringify(before.get(path) ?? null) !==
					JSON.stringify(after.get(path) ?? null)
			)
			.map((path) => ({
				key: path,
				label: path,
				group: 'rules',
				from: before.has(path)
					? whoText(before.get(path) ?? null, nameOf)
					: undefined,
				to: after.has(path)
					? whoText(after.get(path) ?? null, nameOf)
					: 'removed'
			}));
	}, [baseline, draft, nameOf]);
	const dirty = changes.length > 0;
	useLeaveGuard(dirty, changes.length);

	function update(key: string, change: Partial<DraftRule>) {
		setRefusal(null);
		setDraft((current) =>
			current.map((rule) => (rule.key === key ? { ...rule, ...change } : rule))
		);
	}

	function setKind(rule: DraftRule, kind: WhoKind) {
		const who: Who =
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
			{ key: nextKey(), path: '', who: { kind: 'groups', groupIds: [] } }
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
		return `${where}: ${whoText(w.from, nameOf)} → ${whoText(w.to, nameOf)}`;
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
						who: bodyOf(rule.who)
					}))
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
		const found = widenings(before, after);
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

	const rows = draft.map((rule) => {
		const isRoot = rule.root === true;
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
			<AccessCheck
				bucketId={bucketId}
				app={app}
				draft={dirty ? rulesOf(draft) : null}
				nameOf={nameOf}
			/>
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
function AccessCheck({
	bucketId,
	app,
	draft,
	nameOf
}: {
	bucketId: string;
	app: AppView;
	/* The edited rules, or null when nothing is edited. */
	draft: PathRule[] | null;
	nameOf: (id: string) => string | null;
}) {
	const [address, setAddress] = useState('');
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

	const person = personOfView(
		chosen
			? {
					active: chosen.view.active,
					lockedLocally: chosen.view.lockedLocally,
					groups: chosen.view.groups
				}
			: null
	);
	const typed = address.trim();
	const target = typed ? targetOf(typed) : null;
	const saved = typed
		? checkAccess({
				rules: rulesOfView(app.rules),
				method,
				address: typed,
				person
			})
		: null;
	const edited =
		typed && draft
			? checkAccess({ rules: draft, method, address: typed, person })
			: null;

	function reasonOf(decision: Decision, rules: readonly PathRule[]): string {
		const who = chosen?.email ?? 'The person';
		const rule = rules.find(
			(r) => norm(r.path) === norm(decision.rule ?? '\u0000')
		);
		const ruleLabel = rule ? pathText(rule.path, rule.who) : decision.rule;
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
						by {pathText(rule.path, rule.who)}
					</Typography.Text>
				)}
				<Typography.Text>{reasonOf(decision, rules)}</Typography.Text>
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
