import { useCallback, useEffect, useState } from 'react';
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
import { useRoute } from '../frame/router.js';
import { EmptyState, LoadFailed, NoMatch } from '../frame/states.js';

interface AuditEntry {
	_id: string;
	actorId: string;
	actorEmail: string;
	action: string;
	targetType: string;
	targetId: string;
	targetScope: string | null;
	attributes: string[];
	cascade: Record<string, number> | null;
	/* Absent or null on an entry made in the console: the field was added after the trail began. */
	viaSurface?: 'mcp' | 'scim' | 'upstream' | null;
	viaClientId?: string | null;
	timestamp: string;
}

type Surface = 'console' | 'mcp' | 'scim' | 'upstream';

const SURFACE_OPTIONS: { label: string; value: Surface }[] = [
	{ label: 'Console', value: 'console' },
	{ label: 'MCP', value: 'mcp' },
	{ label: 'SCIM', value: 'scim' },
	{ label: 'Upstream provider', value: 'upstream' }
];

/*
 * The sentinel a provisioning connection is recorded under (lib/admin/audit/record.ts). Shown as what it is,
 * because the raw value in the email column reads as a malformed address rather than as a directory.
 */
const CONNECTION_ACTOR_PREFIX = 'connection:';

/* An upstream identity provider's global token revocation: `upstream:<bucketId>:<providerId>` (specs/072). */
const UPSTREAM_ACTOR_PREFIX = 'upstream:';

function actorLabel(row: AuditEntry, email: string): string {
	if (row.actorId.startsWith(CONNECTION_ACTOR_PREFIX)) {
		return `SCIM connection ${row.actorId.slice(CONNECTION_ACTOR_PREFIX.length)}`;
	}
	if (row.actorId.startsWith(UPSTREAM_ACTOR_PREFIX)) {
		const provider = row.actorId.split(':').at(-1);
		return `Identity provider ${provider ?? ''}`.trim();
	}
	return email;
}

interface AuditPage {
	entries: AuditEntry[];
	total: number;
	page: number;
	pageSize: number;
}

interface Filters {
	actor: string;
	action: string;
	targetType: string;
	targetId: string;
	targetScope: string;
	from: string;
	to: string;
	viaSurface: Surface | '';
}

const EMPTY_FILTERS: Filters = {
	actor: '',
	action: '',
	targetType: '',
	targetId: '',
	targetScope: '',
	from: '',
	to: '',
	viaSurface: ''
};

/*
 * The filters a link opened the page with (specs/081: a bucket's Overview links to its own entries). Read
 * once, when the page mounts; after that the boxes are the operator's.
 */
function filtersFrom(query: URLSearchParams): Filters {
	const filters = { ...EMPTY_FILTERS };
	for (const key of [
		'actor',
		'action',
		'targetType',
		'targetId',
		'targetScope',
		'from',
		'to'
	] as const) {
		const value = query.get(key);
		if (value) filters[key] = value;
	}
	return filters;
}

const TEXT_FILTERS = [
	{ name: 'actor' as const, placeholder: 'Actor (email or id)', width: 220 },
	{ name: 'action' as const, placeholder: 'Action', width: 180 },
	{ name: 'targetType' as const, placeholder: 'Target type', width: 160 },
	{ name: 'targetId' as const, placeholder: 'Target id', width: 200 },
	{ name: 'targetScope' as const, placeholder: 'Bucket (scope)', width: 180 }
];

/*
 * `from`/`to` arrive as YYYY-MM-DD from a native date input and are widened to whole days, so a window
 * of one day includes everything that happened that day in the viewer's own timezone.
 */
function toBound(day: string, edge: 'start' | 'end'): string {
	const suffix = edge === 'start' ? 'T00:00:00' : 'T23:59:59.999';
	return new Date(`${day}${suffix}`).toISOString();
}

/* The applied filters in a few words, for the "nothing matches" answer. */
function describeFilters(filters: Filters): string {
	const parts: string[] = [];
	for (const { name, placeholder } of TEXT_FILTERS) {
		const value = filters[name].trim();
		if (value) parts.push(`${placeholder}: ${value}`);
	}
	if (filters.viaSurface) {
		const surface = SURFACE_OPTIONS.find((o) => o.value === filters.viaSurface);
		parts.push(`Surface: ${surface?.label ?? filters.viaSurface}`);
	}
	if (filters.from) parts.push(`from ${filters.from}`);
	if (filters.to) parts.push(`to ${filters.to}`);
	return parts.join(', ');
}

function buildQuery(filters: Filters, page: number, pageSize: number): string {
	const params = new URLSearchParams();
	for (const { name } of TEXT_FILTERS) {
		const value = filters[name].trim();
		if (value) params.set(name, value);
	}
	if (filters.from) params.set('from', toBound(filters.from, 'start'));
	if (filters.to) params.set('to', toBound(filters.to, 'end'));
	if (filters.viaSurface) params.set('viaSurface', filters.viaSurface);
	params.set('page', String(page));
	params.set('pageSize', String(pageSize));
	return params.toString();
}

export function Audit() {
	const [page, setPage] = useState<AuditPage | null>(null);
	const [loading, setLoading] = useState(true);
	/*
	 * A failed load used to leave the previous page, or an empty table, on screen without a word — which
	 * reads as "nothing happened" on the one page whose job is to say what did.
	 */
	const [failed, setFailed] = useState<string | null>(null);
	const { query } = useRoute();
	const [initial] = useState<Filters>(() => filtersFrom(query));
	const [filters, setFilters] = useState<Filters>(initial);
	/* What the page on screen was filtered by, as opposed to what is typed into the boxes now. */
	const [applied, setApplied] = useState<Filters>(initial);
	const [current, setCurrent] = useState(1);
	const [pageSize, setPageSize] = useState(50);

	/*
	 * Filters are passed in rather than read from state, so a request always uses the values the caller
	 * meant — resetting and reloading in one action would otherwise send the state it just replaced.
	 */
	// Every state write follows an await, so the mount effect calls this without setting
	// `loading` first; `load` is the reload, which does.
	const fetchPage = useCallback(
		async (active: Filters, atPage: number, size: number) => {
			try {
				const result = await request<AuditPage>(
					'GET',
					`/admin/api/audit?${buildQuery(active, atPage, size)}`
				);
				setApplied(active);
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
			} finally {
				setLoading(false);
			}
		},
		[]
	);
	function load(active: Filters, atPage: number, size: number) {
		setLoading(true);
		return fetchPage(active, atPage, size);
	}

	useEffect(() => {
		void fetchPage(initial, 1, 50);
	}, [fetchPage, initial]);

	function apply() {
		setCurrent(1);
		void load(filters, 1, pageSize);
	}

	function reset() {
		setFilters(EMPTY_FILTERS);
		setCurrent(1);
		void load(EMPTY_FILTERS, 1, pageSize);
	}

	const filtered = describeFilters(applied) !== '';

	const columns = [
		{
			title: 'Time',
			dataIndex: 'timestamp',
			render: (value: string) => new Date(value).toLocaleString()
		},
		{
			title: 'Actor',
			dataIndex: 'actorEmail',
			render: (email: string, row: AuditEntry) => (
				<Space
					orientation="vertical"
					size={0}
				>
					<Typography.Text>{actorLabel(row, email)}</Typography.Text>
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
			render: (attributes: string[]) =>
				attributes.length === 0 ? (
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
		 * What else the action carried with it: what a deletion destroyed, the projects that moved with a
		 * bucket, the members an upgrade removed. A separate column from "Fields set" rather than more
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
					: row.action === 'group.member.remove'
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

			<Card size="small">
				<Space wrap>
					{TEXT_FILTERS.map(({ name, placeholder, width }) => (
						<Input
							key={name}
							placeholder={placeholder}
							value={filters[name]}
							style={{ width }}
							onChange={(e) =>
								setFilters({ ...filters, [name]: e.target.value })
							}
						/>
					))}
					{/*
					 * `max`/`min` cross-bound the two fields, so a backwards window cannot be submitted from
					 * here at all and the server's 422 stays a backstop rather than a routine error.
					 */}
					<Select<Surface>
						placeholder="Surface"
						aria-label="Surface"
						allowClear
						style={{ width: 140 }}
						options={SURFACE_OPTIONS}
						value={filters.viaSurface || undefined}
						onChange={(value: Surface | undefined) =>
							setFilters({ ...filters, viaSurface: value ?? '' })
						}
					/>
					<Input
						type="date"
						aria-label="From date"
						value={filters.from}
						max={filters.to || undefined}
						style={{ width: 160 }}
						onChange={(e) => setFilters({ ...filters, from: e.target.value })}
					/>
					<Input
						type="date"
						aria-label="To date"
						value={filters.to}
						min={filters.from || undefined}
						style={{ width: 160 }}
						onChange={(e) => setFilters({ ...filters, to: e.target.value })}
					/>
					<Button
						type="primary"
						onClick={apply}
					>
						Apply
					</Button>
					<Button onClick={reset}>Reset</Button>
				</Space>
			</Card>

			{failed !== null ? (
				<LoadFailed
					reason={failed}
					onRetry={() => void load(applied, current, pageSize)}
				/>
			) : (
				<Table<AuditEntry>
					rowKey="_id"
					loading={loading}
					dataSource={page?.entries ?? []}
					columns={columns}
					locale={{
						emptyText: filtered ? (
							<NoMatch
								query={describeFilters(applied)}
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
							void load(applied, nextPage, nextSize);
						}
					}}
				/>
			)}
		</Space>
	);
}
