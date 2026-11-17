import { useCallback, useEffect, useMemo, useState } from 'react';
import { Alert, Button, Flex, Select, Tag, Tooltip, Typography } from 'antd';
import { Link, useNavigate, useRoute } from '../../frame/router.js';
import { request } from '../../frame/request.js';
import { EmptyState, LoadFailed } from '../../frame/states.js';
import { apiHref, behindProxyHref, userHref } from '../../frame/routes.js';

type Kind = 'signIn' | 'app' | 'api';
type Outcome = 'let_in' | 'sign_in_again' | 'refused';

export interface ActivityRow {
	id: string;
	day: string;
	kind: Kind;
	outcome: Outcome;
	reason: string;
	words: {
		outcome: string;
		reason: string;
		sawText: string | null;
		method: string | null;
		device: string | null;
	};
	place: {
		clientId?: string;
		appId?: string;
		appOrigin?: string;
		resource?: string;
		rule?: string;
		tool?: string;
		providerId?: string;
		name: string | null;
	};
	client: string | null;
	address: string | null;
	addressFrom: 'sign_in' | 'proxy' | null;
	facts: { country: string | null; categories: string[] } | null;
	lookup: {
		asn: number | null;
		asName: string | null;
		regionCode: string | null;
		region: string | null;
		city: string | null;
	} | null;
	newAddress: boolean;
	count: number;
	/* A use row (specs/134): the proxy's checks behind it, said only in a tooltip, never as a count of visits. */
	checks: string | null;
	tools: {
		names: string[];
		more: number;
		atBound: boolean;
		words: string;
	} | null;
	firstAt: string;
	lastAt: string;
	check: { app: string } | { api: string } | null;
}

interface ActivityPage {
	recording: boolean;
	recordingBegan: string | null;
	keptDays: number;
	rows: ActivityRow[];
	next: string | null;
	busyDays: string[];
	lookupState: LookupState;
}

type LookupState = 'on' | 'off' | 'no-key' | 'used-up';

/* Why an address has no owner and location (specs/136 contracts/console.md §1), as the instance stands now. */
const NOT_LOOKED_UP: Record<LookupState, string> = {
	off: 'Looking up network owner and location is turned off in Settings.',
	'no-key':
		'This server has no FoxTrust key yet. A super administrator can see why in Settings.',
	'used-up':
		"Today's lookups are used up. Records from the next UTC day get them again.",
	on: 'Not looked up when this record was written: FoxTrust did not answer in time, or the record is older.'
};

/* "AS64500 Example Net · Bavaria, Munich", with nothing said for a part FoxTrust did not know. */
function ownerAndLocation(lookup: NonNullable<ActivityRow['lookup']>): string {
	const owner = [
		lookup.asn === null ? null : `AS${String(lookup.asn)}`,
		lookup.asName
	]
		.filter((part): part is string => part !== null)
		.join(' ');
	const place = [lookup.region, lookup.city]
		.filter((part): part is string => part !== null)
		.join(', ');
	return [owner, place].filter((part) => part !== '').join(' · ');
}

const KINDS: { value: Kind | 'all'; label: string }[] = [
	{ value: 'all', label: 'All kinds' },
	{ value: 'signIn', label: 'Sign-ins' },
	{ value: 'app', label: 'Apps' },
	{ value: 'api', label: 'APIs' }
];

const OUTCOMES: { value: Outcome | 'all'; label: string }[] = [
	{ value: 'all', label: 'All outcomes' },
	{ value: 'let_in', label: 'Let in' },
	{ value: 'sign_in_again', label: 'Asked to sign in again' },
	{ value: 'refused', label: 'Refused' }
];

const CATEGORY_WORDS: Record<string, string> = {
	tor: 'Tor',
	vpn: 'VPN',
	hosting: 'hosting'
};

const PAGE = 50;

export function dateWords(at: string): string {
	return new Date(at).toLocaleDateString(undefined, {
		day: 'numeric',
		month: 'short',
		year: 'numeric'
	});
}

function timeWords(at: string): string {
	return new Date(at).toLocaleTimeString(undefined, {
		hour: '2-digit',
		minute: '2-digit'
	});
}

/* The browser's own date of the row's latest event: rows are grouped by the reader's day, not the server's. */
function localDay(at: string): string {
	const d = new Date(at);
	return `${String(d.getFullYear())}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

function countryName(code: string): string {
	try {
		return (
			new Intl.DisplayNames(undefined, { type: 'region' }).of(code) ?? code
		);
	} catch {
		return code;
	}
}

function placeOf(row: ActivityRow): string {
	if (row.place.name) return row.place.name;
	if (row.kind === 'api') return row.place.resource ?? 'An API';
	if (row.kind === 'app') return 'An app behind the proxy';
	return row.place.appOrigin ?? row.place.clientId ?? 'An application';
}

function checkHref(
	bucketId: string,
	userId: string,
	row: ActivityRow
): string | null {
	if (!row.check) return null;
	const params = new URLSearchParams({ person: userId });
	if ('app' in row.check) {
		if (row.place.rule) params.set('path', row.place.rule);
		return `${behindProxyHref(bucketId, row.check.app, 'access')}?${params.toString()}`;
	}
	if (row.place.tool && row.place.tool !== '*another') {
		params.set('tool', row.place.tool);
	}
	return `${apiHref(bucketId, row.check.api, 'access')}?${params.toString()}`;
}

function Address({
	row,
	lookupState
}: {
	row: ActivityRow;
	lookupState: LookupState;
}) {
	if (row.kind === 'api') return null;
	if (!row.address) {
		if (row.kind !== 'app') return null;
		return (
			<Tooltip title="Your proxy didn't prove with this project's proxy key that it passes people's addresses.">
				<Typography.Text type="secondary">no address</Typography.Text>
			</Tooltip>
		);
	}
	const facts = row.facts
		? [
				row.facts.country ? countryName(row.facts.country) : null,
				...row.facts.categories.map((c) => CATEGORY_WORDS[c] ?? c)
			].filter((part): part is string => part !== null)
		: [];
	return (
		<>
			<Typography.Text code>{row.address}</Typography.Text>
			{row.addressFrom === 'proxy' && (
				<Typography.Text type="secondary">
					{' '}
					as your proxy reported it
				</Typography.Text>
			)}
			{facts.length > 0 && (
				<Tooltip title="Known to FoxTrust when this was recorded. IP Geolocation by DB-IP.">
					<Typography.Text type="secondary">
						{' '}
						· {facts.join(' · ')}
					</Typography.Text>
				</Tooltip>
			)}
			{row.lookup ? (
				<Tooltip title="Network owner and location, looked up at FoxTrust when this was recorded.">
					<Typography.Text type="secondary">
						{' '}
						· {ownerAndLocation(row.lookup)}
					</Typography.Text>
				</Tooltip>
			) : (
				<Tooltip title={NOT_LOOKED_UP[lookupState]}>
					<Typography.Text type="secondary">
						{' '}
						· Owner and location not looked up
					</Typography.Text>
				</Tooltip>
			)}
		</>
	);
}

/*
 * What the person used that day at an app or an API (specs/134 contracts/console.md, У6): a span of time and no count,
 * because one page is many checks; the checks are in the tooltip, the tools beside an API's row.
 */
function UseRow({ row }: { row: ActivityRow }) {
	const [open, setOpen] = useState(false);
	const first = timeWords(row.firstAt);
	const last = timeWords(row.lastAt);
	const span = first === last ? last : `${first}–${last}`;
	return (
		<Flex
			wrap
			gap={8}
			align="baseline"
			style={{
				padding: '8px 0',
				borderBottom: '1px solid rgba(5, 5, 5, 0.06)'
			}}
		>
			<Tooltip title={row.checks}>
				<Typography.Text type="secondary">{span}</Typography.Text>
			</Tooltip>
			<Typography.Text>
				{row.kind === 'api' ? (
					<>
						<Typography.Text strong>{placeOf(row)}</Typography.Text>
						{row.client ? ` through ${row.client}` : ''}
					</>
				) : (
					<>
						Used <Typography.Text strong>{placeOf(row)}</Typography.Text>
					</>
				)}
			</Typography.Text>
			{row.tools &&
				(open ? (
					<Typography.Text type="secondary">
						{row.tools.names.join(', ')}
						{row.tools.atBound ? ' and perhaps more' : ''}
					</Typography.Text>
				) : (
					<>
						<Typography.Text type="secondary">
							{row.tools.words}
						</Typography.Text>
						{row.tools.more > 0 && (
							<Button
								type="link"
								size="small"
								onClick={() => {
									setOpen(true);
								}}
							>
								Show all
							</Button>
						)}
					</>
				))}
		</Flex>
	);
}

function Row({
	bucketId,
	userId,
	row,
	lookupState
}: {
	bucketId: string;
	userId: string;
	row: ActivityRow;
	lookupState: LookupState;
}) {
	if (row.reason === 'used') return <UseRow row={row} />;
	const check =
		row.outcome === 'let_in' ? null : checkHref(bucketId, userId, row);
	const when =
		row.count > 1
			? `${timeWords(row.firstAt)}–${timeWords(row.lastAt)}`
			: timeWords(row.lastAt);
	const outcome =
		row.count > 1
			? `${row.words.outcome} ${String(row.count)} times`
			: row.words.outcome;
	return (
		<Flex
			vertical
			gap={2}
			style={{
				padding: '8px 0',
				borderBottom: '1px solid rgba(5, 5, 5, 0.06)'
			}}
		>
			<Flex
				wrap
				gap={8}
				align="baseline"
			>
				<Typography.Text type="secondary">{when}</Typography.Text>
				<Tag
					color={
						row.outcome === 'let_in'
							? 'green'
							: row.outcome === 'refused'
								? 'red'
								: 'gold'
					}
				>
					{outcome}
				</Tag>
				<Typography.Text strong>{placeOf(row)}</Typography.Text>
				{row.kind === 'api' && row.client && (
					<Typography.Text type="secondary">
						through {row.client}
					</Typography.Text>
				)}
				{row.newAddress && <Tag>New address</Tag>}
			</Flex>
			<Flex
				wrap
				gap={8}
				align="baseline"
			>
				{row.outcome === 'let_in' ? (
					<>
						{row.words.method && (
							<Typography.Text>{row.words.method}</Typography.Text>
						)}
						<Address
							row={row}
							lookupState={lookupState}
						/>
						{row.words.device && (
							<Tooltip title="As the browser reported it.">
								<Typography.Text type="secondary">
									{row.words.device}
								</Typography.Text>
							</Tooltip>
						)}
					</>
				) : (
					<>
						<Typography.Text>{row.words.reason}</Typography.Text>
						<Address
							row={row}
							lookupState={lookupState}
						/>
					</>
				)}
				{check && <Link href={check}>Check this now</Link>}
			</Flex>
			{row.words.sawText && (
				<Typography.Text type="secondary">
					They saw: “{row.words.sawText}”
				</Typography.Text>
			)}
		</Flex>
	);
}

/*
 * What this server decided about the person (specs/133 contracts/console.md): sign-ins, failed sign-ins and stops,
 * and what apps behind the proxy and APIs checked at it asked or refused, newest first, grouped by the reader's day.
 * The filters live in the address, like the Users list, so a link shows the same view.
 */
export function UserActivityTab({
	bucketId,
	userId
}: {
	bucketId: string;
	userId: string;
}) {
	const { query } = useRoute();
	const navigate = useNavigate();
	const kind = (query.get('kind') ?? 'all') as Kind | 'all';
	const outcome = (query.get('outcome') ?? 'all') as Outcome | 'all';
	const [pages, setPages] = useState<ActivityPage[]>([]);
	const [loadError, setLoadError] = useState<string | null>(null);
	const [loading, setLoading] = useState(true);
	/* Whether recording began within the kept days, judged when a page arrives rather than on every render. */
	const [recent, setRecent] = useState(false);

	// Every state write follows an await, so the effect below calls this without setting `loading` first.
	const load = useCallback(
		async (before: string | null) => {
			try {
				const result = await request<ActivityPage>(
					'POST',
					`/admin/api/projects/${encodeURIComponent(bucketId)}/users/${encodeURIComponent(userId)}/activity`,
					{
						...(kind === 'all' ? {} : { kind }),
						...(outcome === 'all' ? {} : { outcome }),
						...(before ? { before } : {}),
						limit: PAGE
					}
				);
				if (result.ok) {
					setPages((earlier) =>
						before ? [...earlier, result.data] : [result.data]
					);
					const began = result.data.recordingBegan;
					setRecent(
						began !== null &&
							Date.now() - new Date(began).getTime() <
								result.data.keptDays * 86_400_000
					);
					setLoadError(null);
				} else {
					setLoadError(result.error.message);
				}
			} finally {
				setLoading(false);
			}
		},
		[bucketId, userId, kind, outcome]
	);
	useEffect(() => {
		void load(null);
	}, [load]);

	const go = (changes: Record<string, string>) => {
		const params = new URLSearchParams(query);
		for (const [key, value] of Object.entries(changes)) {
			if (value === 'all') params.delete(key);
			else params.set(key, value);
		}
		const qs = params.toString();
		void navigate(
			`${userHref(bucketId, userId, 'activity')}${qs ? `?${qs}` : ''}`,
			{
				replace: true,
				scroll: false
			}
		);
	};

	const rows = useMemo(() => pages.flatMap((page) => page.rows), [pages]);
	const lookupState = pages.at(-1)?.lookupState ?? 'on';
	const busy = useMemo(
		() => new Set(pages.flatMap((page) => page.busyDays)),
		[pages]
	);
	const days = useMemo(() => {
		const grouped = new Map<string, ActivityRow[]>();
		for (const row of rows) {
			const day = localDay(row.lastAt);
			const list = grouped.get(day) ?? [];
			list.push(row);
			grouped.set(day, list);
		}
		return [...grouped.entries()];
	}, [rows]);
	const first = pages.at(0);
	const last = pages.at(-1);
	const began = first?.recordingBegan ?? null;

	if (loadError !== null) {
		return (
			<LoadFailed
				reason={loadError}
				onRetry={() => {
					setLoading(true);
					void load(null);
				}}
			/>
		);
	}

	return (
		<Flex
			vertical
			gap={12}
		>
			<Typography.Text type="secondary">
				Sign-ins, and what apps behind your proxy and APIs checked at it
				answered. Kept for {String(first?.keptDays ?? 90)} days. Sign-ins and
				refusals are recorded up to a minute late, use of apps up to five
				minutes.
				{recent && began && (
					<>
						{' '}
						Recording began on {dateWords(began)}. Nothing earlier was recorded.
					</>
				)}
			</Typography.Text>
			{first?.recording === false && (
				<Alert
					type="info"
					showIcon
					title="Recording is turned off for this server. What was recorded stays until it expires."
				/>
			)}
			<Flex
				wrap
				gap={8}
			>
				<Select
					aria-label="Outcome"
					value={outcome}
					options={OUTCOMES}
					style={{ minWidth: 200 }}
					onChange={(value) => go({ outcome: value })}
				/>
				<Select
					aria-label="Kind"
					value={kind}
					options={KINDS}
					style={{ minWidth: 140 }}
					onChange={(value) => go({ kind: value })}
				/>
			</Flex>
			{!loading && rows.length === 0 && (
				<EmptyState
					purpose={
						began
							? `No sign-ins, refusals or use of apps since recording began on ${dateWords(began)}.`
							: 'No sign-ins, refusals or use of apps recorded yet.'
					}
				/>
			)}
			{days.map(([day, list]) => {
				const serverDays = new Set(list.map((row) => row.day));
				const missing = [...serverDays].some((d) => busy.has(d));
				return (
					<Flex
						key={day}
						vertical
					>
						<Typography.Title
							level={5}
							style={{ marginBottom: 0 }}
						>
							{dateWords(list[0].lastAt)}
						</Typography.Title>
						{missing && (
							<Typography.Text type="warning">
								On this day this server was too busy to record everything for
								this project. This day may be missing entries.
							</Typography.Text>
						)}
						{list.map((row) => (
							<Row
								key={row.id}
								bucketId={bucketId}
								userId={userId}
								row={row}
								lookupState={lookupState}
							/>
						))}
					</Flex>
				);
			})}
			{last?.next && (
				<Button
					loading={loading}
					onClick={() => {
						setLoading(true);
						void load(last.next);
					}}
				>
					Show earlier days
				</Button>
			)}
		</Flex>
	);
}
