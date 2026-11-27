import { useCallback, useEffect, useRef, useState } from 'react';
import { Card, Flex, Input, Select, Tag, Typography } from 'antd';
import { request } from '../../frame/request.js';
import { useRoute } from '../../frame/router.js';
import { usersApi, type EndUser } from '../users/endUser.js';
import { personOfView } from '../../../../behind_proxy/access_check.js';
import {
	decideApiCall,
	type ApiDecision,
	type ApiView
} from '../../../../behind_proxy/api_decision.js';
import type {
	ConditionKind,
	NetworkFacts
} from '../../../../behind_proxy/conditions.js';
import { HEADER_VALIDATING_VERSION } from '../../../../behind_proxy/tools.js';
import { KIND_LABELS } from '../behind-proxy/conditionsText.js';

/*
 * "Check access" for an API checked at the proxy (specs/131 research R9): a request described in, the answer the
 * proxy's check would give out, for the saved table and the edited one. It runs `decideApiCall` here, the function the
 * check runs, so it cannot answer differently. There is no dry-run route: it would need an audit entry for every
 * click. The only server calls are reads: the people of the project, and what this server's copy of FoxTrust's
 * snapshot says about an address.
 */

interface PersonOption {
	id: string;
	email: string;
	view: EndUser;
}

/* The lookup route's answer (specs/129 contracts/admin-and-proxy.md). */
interface FactsAnswer {
	facts: NetworkFacts;
	state: 'off' | 'not-yet' | 'current' | 'stale';
	ageSeconds: number | null;
}

type Kind = 'tool' | 'other_tool' | 'other_method' | 'old_client';

const NOBODY = '';

const SIGNED_IN_OPTIONS = [
	{ value: 0, label: 'just now' },
	{ value: 120, label: '2 hours ago' },
	{ value: 1440, label: '1 day ago' },
	{ value: 10080, label: '7 days ago' },
	{ value: 20160, label: '14 days ago' }
];

const OUTCOMES: Record<
	ApiDecision['outcome'],
	{ color: string; label: string }
> = {
	allow: { color: 'success', label: 'Allowed' },
	refuse: { color: 'error', label: 'Refused' },
	insufficient: { color: 'error', label: 'Refused' },
	sign_in: { color: 'warning', label: 'Asked to sign in again' },
	unknown: { color: 'default', label: 'Not known' }
};

/* A `datetime-local` value, read as the browser's own clock; empty means now. */
function momentOf(value: string): number {
	if (value === '') return Date.now();
	const at = Date.parse(value);
	return Number.isNaN(at) ? Date.now() : at;
}

function reasonOf(decision: ApiDecision, who: string): string {
	switch (decision.outcome) {
		case 'allow':
			return decision.tool
				? `${who} may call ${decision.tool}.`
				: `${who} may make this request.`;
		case 'insufficient':
			return `The app's token lacks ${decision.needed.join(', ')}, which ${decision.tool} needs.`;
		case 'sign_in':
			return decision.unmet.passkey
				? 'The sign-in was not with a passkey, which this API requires, so the app is asked to sign in again.'
				: decision.unmet.code
					? 'The sign-in was not two-step, which this API requires, so the app is asked to sign in again.'
					: 'The sign-in is older than this API allows, so the app is asked to sign in again.';
		case 'unknown':
			return `Not enough to judge: ${decision.kinds
				.map((kind: ConditionKind) => KIND_LABELS[kind].toLowerCase())
				.join(
					', '
				)}. Give an address the network facts can be looked up for, or the missing input.`;
		case 'refuse':
			switch (decision.reason) {
				case 'no_person':
					return 'The token stands for no person this project can name, so conditions about people, and a sign-in requirement, refuse it.';
				case 'cannot_sign_in':
					return `${who} is deactivated or locked, so this project does not let them in.`;
				case 'not_in_group':
					return decision.tool
						? `${who} is not in the groups that may call ${decision.tool}, or not in the API's own.`
						: `${who} is not in the groups that may call this API.`;
				case 'attribute_mismatch':
					return `${who} does not have the attribute this API asks for.`;
				case 'not_from_network':
					return 'The address is not one the conditions let in.';
				case 'network_facts_unknown':
					return 'Network facts are off or out of date on this server, so anything that relies on them is closed for everyone.';
				case 'outside_hours':
					return 'It is outside the hours the conditions allow.';
				case 'old_client':
					return 'Apps too old to say which tool they call are refused.';
				case 'tool_not_listed':
					return 'The table does not list this tool, and any other tool is refused.';
				case 'tool_unnamed':
					return 'The app called a tool without naming it.';
				case 'bad_mcp_header':
					return 'The app sent an MCP header the check cannot read.';
			}
	}
}

export function ApiCheckAccess({
	bucketId,
	scopes,
	saved,
	edited
}: {
	bucketId: string;
	/* The API's scopes, the ones an app's token for it may hold. */
	scopes: readonly string[];
	saved: ApiView;
	/* The table being edited, or null when nothing is edited. */
	edited: ApiView | null;
}) {
	const tools = (edited ?? saved).tools?.rows.map((row) => row.name) ?? [];
	/*
	 * "Check this now" on a person's activity (specs/133 FR-023): the person and the tool row arrive in the address, and
	 * the check answers at once against today's rules. Read when the panel opens.
	 */
	const { query } = useRoute();
	const prefillPerson = query.get('person');
	const [kind, setKind] = useState<Kind>('tool');
	const [toolName, setToolName] = useState(() => query.get('tool') ?? '');
	const [otherName, setOtherName] = useState('');
	const [held, setHeld] = useState<string[]>([...scopes]);
	const [from, setFrom] = useState('');
	const [moment, setMoment] = useState('');
	const [signedInAgo, setSignedInAgo] = useState(0);
	const [signInMethod, setSignInMethod] = useState<
		'password' | 'code' | 'passkey'
	>('password');
	const [personId, setPersonId] = useState(NOBODY);
	const [people, setPeople] = useState<PersonOption[]>([]);
	const [chosen, setChosen] = useState<PersonOption | null>(null);
	const [lookedUp, setLookedUp] = useState<{
		address: string;
		answer: FactsAnswer;
	} | null>(null);
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

	useEffect(() => {
		if (!prefillPerson) return;
		void request<EndUser>('GET', usersApi(bucketId, prefillPerson)).then(
			(result) => {
				if (!result.ok) return;
				const option = {
					id: result.data._id,
					email: result.data.email,
					view: result.data
				};
				setPeople((shown) =>
					shown.some((p) => p.id === option.id) ? shown : [option, ...shown]
				);
				setPersonId(option.id);
				setChosen(option);
			}
		);
		// Once per opening: later edits are the administrator's own.
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, []);

	/* Asked only when some condition relies on network facts: the decision runs here and cannot hold the snapshot. */
	const wantsFacts = [saved, edited].some((view) =>
		[
			...(view?.tools?.access?.conditions ?? []),
			...(view?.tools?.rows.flatMap((row) => row.conditions ?? []) ?? [])
		].some((c) => c.kind === 'network' && c.facts)
	);
	useEffect(() => {
		const typed = from.trim();
		if (!wantsFacts || typed === '') return;
		let current = true;
		const timer = setTimeout(() => {
			void request<FactsAnswer>('POST', '/admin/api/network-facts/lookup', {
				address: typed
			}).then((result) => {
				if (current && result.ok) {
					setLookedUp({ address: typed, answer: result.data });
				}
			});
		}, 400);
		return () => {
			current = false;
			clearTimeout(timer);
		};
	}, [from, wantsFacts]);
	const facts =
		lookedUp && lookedUp.address === from.trim() ? lookedUp.answer : null;

	const at = momentOf(moment);
	const viewed = personOfView(chosen ? chosen.view : null);
	const person = viewed
		? {
				groupIds: viewed.groupIds,
				attributes: viewed.attributes ?? {},
				canSignIn: viewed.canSignIn
			}
		: null;
	const name = kind === 'tool' ? toolName || tools[0] || '' : otherName;
	const headers =
		kind === 'old_client'
			? { method: 'tools/call', name: name || null, protocolVersion: null }
			: kind === 'other_method'
				? {
						method: 'tools/list',
						name: null,
						protocolVersion: HEADER_VALIDATING_VERSION
					}
				: {
						method: 'tools/call',
						name: name || null,
						protocolVersion: HEADER_VALIDATING_VERSION
					};
	const given = {
		token: {
			scopes: new Set(held),
			/* An app acting for itself carries no sign-in. */
			signedInAt: person ? Math.floor(at / 1000) - signedInAgo * 60 : null,
			signedInWithCode: person ? signInMethod !== 'password' : false,
			signedInWithPasskey: person ? signInMethod === 'passkey' : false
		},
		headers,
		person,
		address: from.trim() === '' ? null : from.trim(),
		...(facts ? { network: facts.facts } : {}),
		at,
		explain: true
	};
	const now = decideApiCall(saved, given);
	const after = edited ? decideApiCall(edited, given) : null;
	const who = chosen?.email ?? 'The app';
	const asksSignIn = saved.signIn !== undefined || edited?.signIn !== undefined;

	function verdict(label: string, decision: ApiDecision) {
		const outcome = OUTCOMES[decision.outcome];
		return (
			<Flex
				gap={8}
				wrap
				align="baseline"
			>
				<Typography.Text strong>{label}</Typography.Text>
				<Tag color={outcome.color}>{outcome.label}</Tag>
				<Typography.Text>{reasonOf(decision, who)}</Typography.Text>
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
						aria-label="Person"
						showSearch={{ filterOption: false, onSearch: search }}
						style={{ flex: 1, minWidth: 220 }}
						value={personId}
						onChange={(id: string) => {
							setPersonId(id);
							setChosen(people.find((p) => p.id === id) ?? null);
							setSignInMethod(
								people.find((p) => p.id === id)?.view.totpEnrolled === true
									? 'code'
									: 'password'
							);
						}}
						options={[
							{ value: NOBODY, label: 'No person: an app acting for itself' },
							...people.map((p) => ({ value: p.id, label: p.email }))
						]}
					/>
					<Select
						aria-label="Scopes the app's token holds"
						mode="multiple"
						style={{ flex: 1, minWidth: 220 }}
						value={held}
						onChange={setHeld}
						placeholder="Scopes the app's token holds"
						options={scopes.map((s) => ({ value: s, label: s }))}
					/>
				</Flex>
				<Flex
					gap={8}
					wrap
				>
					<Select
						aria-label="Request"
						style={{ width: 260 }}
						value={kind}
						onChange={setKind}
						options={[
							{ value: 'tool', label: 'Calls a listed tool' },
							{ value: 'other_tool', label: 'Calls another tool' },
							{
								value: 'other_method',
								label: 'Lists tools or starts a session'
							},
							{
								value: 'old_client',
								label: 'An app too old to say which tool it calls'
							}
						]}
					/>
					{kind === 'tool' && (
						<Select
							aria-label="Tool"
							style={{ width: 220 }}
							value={name}
							onChange={setToolName}
							options={tools.map((t) => ({ value: t, label: t }))}
							notFoundContent="No tool listed"
						/>
					)}
					{kind === 'other_tool' && (
						<Input
							aria-label="Tool name"
							style={{ width: 220 }}
							placeholder="export_billing"
							value={otherName}
							onChange={(e) => setOtherName(e.target.value)}
						/>
					)}
				</Flex>
				<Flex
					gap={8}
					wrap
				>
					<Input
						aria-label="Network address of the app"
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
					{asksSignIn && person && (
						<>
							<Select
								aria-label="Signed in"
								style={{ width: 180 }}
								value={signedInAgo}
								onChange={setSignedInAgo}
								options={SIGNED_IN_OPTIONS.map((o) => ({
									value: o.value,
									label: `Signed in ${o.label}`
								}))}
							/>
							<Select
								aria-label="Sign-in method"
								style={{ width: 220 }}
								value={signInMethod}
								onChange={setSignInMethod}
								options={[
									{ value: 'password', label: 'Signed in with password only' },
									{ value: 'code', label: 'Signed in with two steps (code)' },
									{ value: 'passkey', label: 'Signed in with a passkey' }
								]}
							/>
						</>
					)}
				</Flex>
				{verdict(after ? 'Now:' : 'Result:', now)}
				{after && verdict('After save:', after)}
			</Flex>
		</Card>
	);
}
