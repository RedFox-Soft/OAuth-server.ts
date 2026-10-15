import { useCallback, useEffect, useMemo, useState } from 'react';
import {
	Alert,
	Button,
	Card,
	Input,
	Select,
	Space,
	Table,
	Tag,
	Typography
} from 'antd';
import { PageHeader } from '../frame/PageHeader.js';
import { request } from '../frame/request.js';
import { useNavigate, useRoute } from '../frame/router.js';
import { EmptyState, LoadFailed, NoMatch } from '../frame/states.js';
import {
	actorLabel,
	CONNECTION_ACTOR_PREFIX,
	type AuditEntry
} from '../frame/auditEntry.js';

type Surface = 'console' | 'mcp' | 'scim' | 'upstream' | 'self-service';

const SURFACE_OPTIONS: { label: string; value: Surface }[] = [
	{ label: 'Console', value: 'console' },
	{ label: 'MCP', value: 'mcp' },
	{ label: 'SCIM', value: 'scim' },
	{ label: 'Upstream provider', value: 'upstream' },
	{ label: 'End user (self-service)', value: 'self-service' }
];

interface AuditPage {
	entries: AuditEntry[];
	total: number;
	page: number;
	pageSize: number;
}

/*
 * Every filter the trail takes, as the address carries it (specs/085): a filtered view is a link, a reload
 * keeps it, and Back returns to the filter before. `from`/`to` are days (YYYY-MM-DD) here and widened to
 * instants only for the request.
 */
const FILTER_KEYS = [
	'project',
	'connection',
	'actor',
	'action',
	'actionPrefix',
	'targetType',
	'targetId',
	'targetScope',
	'viaSurface',
	'viaClientId',
	'from',
	'to'
] as const;
type FilterKey = (typeof FILTER_KEYS)[number];
type Filters = Record<FilterKey, string>;

const EMPTY_FILTERS = Object.fromEntries(
	FILTER_KEYS.map((k) => [k, ''])
) as Filters;

const CHIP_LABEL: Record<FilterKey, string> = {
	project: 'Project',
	connection: 'Connection',
	actor: 'Actor',
	action: 'Action',
	actionPrefix: 'Action starts with',
	targetType: 'Target type',
	targetId: 'Target',
	targetScope: 'In project',
	viaSurface: 'Surface',
	viaClientId: 'Agent',
	from: 'From',
	to: 'To'
};

function filtersFrom(query: URLSearchParams): Filters {
	const filters = { ...EMPTY_FILTERS };
	for (const key of FILTER_KEYS) filters[key] = query.get(key) ?? '';
	return filters;
}

function auditHref(filters: Filters): string {
	const params = new URLSearchParams();
	for (const key of FILTER_KEYS) {
		const value = filters[key].trim();
		if (value) params.set(key, value);
	}
	const qs = params.toString();
	return qs ? `/admin/audit?${qs}` : '/admin/audit';
}

/*
 * `from`/`to` arrive as YYYY-MM-DD from a native date input and are widened to whole days, so a window
 * of one day includes everything that happened that day in the viewer's own timezone.
 */
function toBound(day: string, edge: 'start' | 'end'): string {
	const suffix = edge === 'start' ? 'T00:00:00' : 'T23:59:59.999';
	return new Date(`${day}${suffix}`).toISOString();
}

function buildQuery(filters: Filters, page: number, pageSize: number): string {
	const params = new URLSearchParams();
	for (const key of FILTER_KEYS) {
		const value = filters[key].trim();
		if (!value) continue;
		if (key === 'from') params.set(key, toBound(value, 'start'));
		else if (key === 'to') params.set(key, toBound(value, 'end'));
		else params.set(key, value);
	}
	params.set('page', String(page));
	params.set('pageSize', String(pageSize));
	return params.toString();
}

/* The boxes: what the operator is typing, applied as a whole by Apply. */
interface Draft {
	actor: string;
	action: string;
	targetType: string;
	targetId: string;
	project: string;
	viaSurface: Surface | '';
	from: string;
	to: string;
}

function draftOf(filters: Filters): Draft {
	return {
		actor: filters.actor,
		// One box for both: a value ending in "." is a prefix ("enduser." is every action on a person).
		action: filters.actionPrefix || filters.action,
		targetType: filters.targetType,
		targetId: filters.targetId,
		project: filters.project,
		viaSurface: filters.viaSurface as Surface | '',
		from: filters.from,
		to: filters.to
	};
}

const TEXT_FILTERS = [
	{ name: 'actor' as const, placeholder: 'Actor (email or id)', width: 220 },
	{
		name: 'action' as const,
		placeholder: 'Action, or prefix ending in .',
		width: 220
	},
	{ name: 'targetType' as const, placeholder: 'Target type', width: 160 },
	{ name: 'targetId' as const, placeholder: 'Target id', width: 200 },
	{ name: 'project' as const, placeholder: 'Project id', width: 160 }
];

export function Audit() {
	const [page, setPage] = useState<AuditPage | null>(null);
	const [loading, setLoading] = useState(true);
	/*
	 * A failed load used to leave the previous page, or an empty table, on screen without a word — which
	 * reads as "nothing happened" on the one page whose job is to say what did.
	 */
	const [failed, setFailed] = useState<string | null>(null);
	const { query } = useRoute();
	const navigate = useNavigate();
	const search = query.toString();
	// The filters on screen are the address's; the boxes are a draft until Apply.
	const applied = useMemo(
		() => filtersFrom(new URLSearchParams(search)),
		[search]
	);
	const [current, setCurrent] = useState(1);
	const [pageSize, setPageSize] = useState(50);
	// Readable names for the project and connection chips, keyed "project:<id>" / "connection:<id>".
	const [names, setNames] = useState<Map<string, string>>(new Map());

	// Every state write follows an await, so the effect below may call it.
	const fetchPage = useCallback(
		async (active: Filters, atPage: number, size: number) => {
			try {
				const result = await request<AuditPage>(
					'GET',
					`/admin/api/audit?${buildQuery(active, atPage, size)}`
				);
				if (!result.ok) {
					const reference = result.error.error_reference;
					setFailed(
						reference
							? `${result.error.message} (reference ${reference})`
							: result.error.message
					);
					return;
				}
				setFailed(null);
				setPage(result.data);
				// A directory's name comes with its entries; a project's from its own read, when readable.
				const found = new Map<string, string>();
				for (const entry of result.data.entries) {
					if (
						entry.actorName &&
						entry.actorId.startsWith(CONNECTION_ACTOR_PREFIX)
					) {
						found.set(
							`connection:${entry.actorId.slice(CONNECTION_ACTOR_PREFIX.length)}`,
							entry.actorName
						);
					}
				}
				for (const key of ['project', 'targetScope'] as const) {
					if (!active[key]) continue;
					const project = await request<{ name: string }>(
						'GET',
						`/admin/api/projects/${encodeURIComponent(active[key])}`
					);
					if (project.ok) found.set(`${key}:${active[key]}`, project.data.name);
				}
				setNames(found);
			} finally {
				setLoading(false);
			}
		},
		[]
	);

	// The address changed — a link followed, a chip removed, Back pressed — so the list starts again.
	useEffect(() => {
		void fetchPage(applied, 1, pageSize);
		// Only a change of filters reloads here; paging asks for its own page below.
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [applied, fetchPage]);

	/*
	 * A filter change is pushed, not replaced, although the console replaces for filters elsewhere: here a
	 * filter is the question being asked, and Back must give the previous question back (specs/085).
	 */
	function go(next: Filters) {
		setCurrent(1);
		setLoading(true);
		void navigate(auditHref(next));
	}

	function reset() {
		go(EMPTY_FILTERS);
	}

	const chips = FILTER_KEYS.filter((k) => applied[k].trim() !== '');
	const chipText = (key: FilterKey) =>
		`${CHIP_LABEL[key]}: ${names.get(`${key}:${applied[key]}`) ?? applied[key]}`;

	const columns = [
		{
			title: 'Time',
			dataIndex: 'timestamp',
			render: (value: string) => new Date(value).toLocaleString()
		},
		{
			title: 'Actor',
			dataIndex: 'actorEmail',
			render: (_: string, row: AuditEntry) => (
				<Space
					orientation="vertical"
					size={0}
				>
					<Typography.Text>{actorLabel(row)}</Typography.Text>
					<Typography.Text
						type="secondary"
						copyable
						style={{ fontSize: 12 }}
					>
						{row.actorId}
					</Typography.Text>
				</Space>
			)
		},
		{
			title: 'Surface',
			dataIndex: 'viaSurface',
			render: (surface: AuditEntry['viaSurface'], row: AuditEntry) =>
				surface === 'mcp' ? (
					<Tag
						color="geekblue"
						title={row.viaClientId ? `agent ${row.viaClientId}` : undefined}
					>
						MCP
					</Tag>
				) : surface === 'scim' ? (
					<Tag color="purple">SCIM</Tag>
				) : surface === 'upstream' ? (
					<Tag color="volcano">Upstream</Tag>
				) : surface === 'self-service' ? (
					<Tag color="cyan">End user</Tag>
				) : (
					<Tag>Console</Tag>
				)
		},
		{
			title: 'Action',
			dataIndex: 'action',
			render: (action: string) => <Tag>{action}</Tag>
		},
		{
			title: 'Target',
			dataIndex: 'targetId',
			render: (targetId: string, row: AuditEntry) => (
				<Space
					orientation="vertical"
					size={0}
				>
					<Typography.Text>{row.targetType}</Typography.Text>
					<Typography.Text
						type="secondary"
						copyable
						style={{ fontSize: 12 }}
					>
						{targetId}
					</Typography.Text>
					{row.from !== undefined || row.to !== undefined ? (
						<Typography.Text
							type="secondary"
							style={{ fontSize: 12 }}
						>
							{row.from ?? 'no address'} → {row.to ?? 'no address'}
						</Typography.Text>
					) : null}
					{row.kid ? (
						<Typography.Text
							type="secondary"
							style={{ fontSize: 12 }}
						>
							key {row.kid}
						</Typography.Text>
					) : null}
					{row.targetScope ? (
						<Typography.Text
							type="secondary"
							style={{ fontSize: 12 }}
						>
							in {row.targetScope}
						</Typography.Text>
					) : null}
				</Space>
			)
		},
		{
			title: 'Fields set',
			dataIndex: 'attributes',
			render: (attributes: string[] | undefined) =>
				!attributes || attributes.length === 0 ? (
					<Typography.Text type="secondary">—</Typography.Text>
				) : (
					<Space
						size={4}
						wrap
					>
						{attributes.map((name) => (
							<Tag key={name}>{name}</Tag>
						))}
					</Space>
				)
		},
		/*
		 * What else the action carried with it: what a deletion destroyed, the applications and APIs that moved with a
		 * project, the members an upgrade removed. A separate column from "Fields set" rather than more
		 * tags in it, because the two answer different questions: one says what the request changed, this
		 * says what else it reached. The verb comes from the action, so a move is never read as a deletion.
		 */
		{
			title: 'Also affected',
			dataIndex: 'cascade',
			render: (cascade: Record<string, number> | null, row: AuditEntry) => {
				const kinds = Object.entries(cascade ?? {});
				const verb = row.action.endsWith('.owner.change')
					? 'moved'
					: row.action === 'team.member.remove'
						? 'removed'
						: 'destroyed';
				return kinds.length === 0 ? (
					<Typography.Text type="secondary">—</Typography.Text>
				) : (
					<Space
						size={4}
						wrap
					>
						{kinds.map(([kind, count]) => (
							<Tag
								key={kind}
								color={verb === 'destroyed' ? 'red' : 'blue'}
							>
								{count} {kind} {verb}
							</Tag>
						))}
					</Space>
				);
			}
		}
	];

	return (
		<Space
			orientation="vertical"
			style={{ width: '100%' }}
			size="middle"
		>
			<PageHeader title="Audit trail" />

			{/*
			 * Entries are written before the change they describe, so no change is applied without a
			 * record. Saying so here is the point of the notice: otherwise a reader takes an entry left by
			 * a request that was then refused as proof the change happened.
			 */}
			<Alert
				type="info"
				showIcon
				title="Entries record what an authorized administrator was about to apply"
				description="Each entry is written immediately before its change, so a change is never applied without a record. An entry is not proof that the change took effect — a later conflict or failure can follow one. Entries are never modified or removed."
			/>

			<FilterBar
				key={search}
				applied={applied}
				chips={chips}
				chipText={chipText}
				onApply={go}
				onReset={reset}
			/>

			{failed !== null ? (
				<LoadFailed
					reason={failed}
					onRetry={() => {
						setLoading(true);
						void fetchPage(applied, current, pageSize);
					}}
				/>
			) : (
				<Table<AuditEntry>
					rowKey="_id"
					loading={loading}
					dataSource={page?.entries ?? []}
					columns={columns}
					locale={{
						emptyText:
							chips.length > 0 ? (
								<NoMatch
									query={chips.map(chipText).join(', ')}
									onClear={reset}
									clearLabel="Clear filters"
								/>
							) : (
								<EmptyState purpose="No administrative change has been recorded yet." />
							)
					}}
					pagination={{
						current,
						pageSize,
						total: page?.total ?? 0,
						showSizeChanger: true,
						pageSizeOptions: ['20', '50', '100', '200'],
						showTotal: (total) => `${total} entries`,
						onChange: (nextPage, nextSize) => {
							setCurrent(nextPage);
							setPageSize(nextSize);
							setLoading(true);
							void fetchPage(applied, nextPage, nextSize);
						}
					}}
				/>
			)}
		</Space>
	);
}

/*
 * The boxes and the applied filters' chips. Keyed by the address in the page, so following a link or pressing
 * Back shows the boxes the address describes rather than what was last typed.
 */
function FilterBar({
	applied,
	chips,
	chipText,
	onApply,
	onReset
}: {
	applied: Filters;
	chips: FilterKey[];
	chipText: (key: FilterKey) => string;
	onApply: (next: Filters) => void;
	onReset: () => void;
}) {
	const [draft, setDraft] = useState<Draft>(() => draftOf(applied));
	const reset = onReset;

	function apply() {
		const action = draft.action.trim();
		onApply({
			...applied,
			actor: draft.actor,
			action: action.endsWith('.') ? '' : action,
			actionPrefix: action.endsWith('.') ? action : '',
			targetType: draft.targetType,
			targetId: draft.targetId,
			project: draft.project,
			viaSurface: draft.viaSurface,
			from: draft.from,
			to: draft.to
		});
	}

	return (
		<Card size="small">
			<Space
				orientation="vertical"
				style={{ width: '100%' }}
			>
				<Space wrap>
					{TEXT_FILTERS.map(({ name, placeholder, width }) => (
						<Input
							key={name}
							placeholder={placeholder}
							aria-label={placeholder}
							value={draft[name]}
							style={{ width }}
							onChange={(e) => setDraft({ ...draft, [name]: e.target.value })}
							onPressEnter={apply}
						/>
					))}
					<Select<Surface>
						placeholder="Surface"
						aria-label="Surface"
						allowClear
						style={{ width: 140 }}
						options={SURFACE_OPTIONS}
						value={draft.viaSurface || undefined}
						onChange={(value: Surface | undefined) =>
							setDraft({ ...draft, viaSurface: value ?? '' })
						}
					/>
					{/*
					 * `max`/`min` cross-bound the two fields, so a backwards window cannot be submitted from
					 * here at all and the server's 422 stays a backstop rather than a routine error.
					 */}
					<Input
						type="date"
						aria-label="From date"
						value={draft.from}
						max={draft.to || undefined}
						style={{ width: 160 }}
						onChange={(e) => setDraft({ ...draft, from: e.target.value })}
					/>
					<Input
						type="date"
						aria-label="To date"
						value={draft.to}
						min={draft.from || undefined}
						style={{ width: 160 }}
						onChange={(e) => setDraft({ ...draft, to: e.target.value })}
					/>
					<Button
						type="primary"
						onClick={apply}
					>
						Apply
					</Button>
					<Button onClick={reset}>Reset</Button>
				</Space>
				{chips.length > 0 && (
					<Space
						wrap
						size={4}
					>
						{chips.map((key) => (
							<Tag
								key={key}
								closable
								aria-label={chipText(key)}
								onClose={(e) => {
									e.preventDefault();
									onApply({ ...applied, [key]: '' });
								}}
							>
								{chipText(key)}
							</Tag>
						))}
					</Space>
				)}
			</Space>
		</Card>
	);
}
