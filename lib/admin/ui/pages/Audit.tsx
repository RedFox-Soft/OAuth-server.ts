import { useEffect, useState } from 'react';
import {
	Alert,
	Button,
	Card,
	Input,
	Space,
	Table,
	Tag,
	Typography
} from 'antd';

interface AuditEntry {
	_id: string;
	actorId: string;
	actorEmail: string;
	action: string;
	targetType: string;
	targetId: string;
	targetScope: string | null;
	attributes: string[];
	timestamp: string;
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
}

const EMPTY_FILTERS: Filters = {
	actor: '',
	action: '',
	targetType: '',
	targetId: '',
	targetScope: '',
	from: '',
	to: ''
};

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

function buildQuery(filters: Filters, page: number, pageSize: number): string {
	const params = new URLSearchParams();
	for (const { name } of TEXT_FILTERS) {
		const value = filters[name].trim();
		if (value) params.set(name, value);
	}
	if (filters.from) params.set('from', toBound(filters.from, 'start'));
	if (filters.to) params.set('to', toBound(filters.to, 'end'));
	params.set('page', String(page));
	params.set('pageSize', String(pageSize));
	return params.toString();
}

export function Audit() {
	const [page, setPage] = useState<AuditPage | null>(null);
	const [loading, setLoading] = useState(true);
	const [filters, setFilters] = useState<Filters>(EMPTY_FILTERS);
	const [current, setCurrent] = useState(1);
	const [pageSize, setPageSize] = useState(50);

	/*
	 * Filters are passed in rather than read from state, so a request always uses the values the caller
	 * meant — resetting and reloading in one action would otherwise send the state it just replaced.
	 */
	async function load(active: Filters, atPage: number, size: number) {
		setLoading(true);
		try {
			const res = await fetch(
				`/admin/api/audit?${buildQuery(active, atPage, size)}`
			);
			if (res.ok) setPage((await res.json()) as AuditPage);
		} finally {
			setLoading(false);
		}
	}

	useEffect(() => {
		load(EMPTY_FILTERS, 1, 50);
	}, []);

	function apply() {
		setCurrent(1);
		load(filters, 1, pageSize);
	}

	function reset() {
		setFilters(EMPTY_FILTERS);
		setCurrent(1);
		load(EMPTY_FILTERS, 1, pageSize);
	}

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
					direction="vertical"
					size={0}
				>
					<Typography.Text>{email}</Typography.Text>
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
			title: 'Action',
			dataIndex: 'action',
			render: (action: string) => <Tag>{action}</Tag>
		},
		{
			title: 'Target',
			dataIndex: 'targetId',
			render: (targetId: string, row: AuditEntry) => (
				<Space
					direction="vertical"
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
		}
	];

	return (
		<Space
			direction="vertical"
			style={{ width: '100%' }}
			size="middle"
		>
			<Typography.Title level={3}>Audit trail</Typography.Title>

			{/*
			 * Entries are written before the change they describe, so no change is applied without a
			 * record. Saying so here is the point of the notice: otherwise a reader takes an entry left by
			 * a request that was then refused as proof the change happened.
			 */}
			<Alert
				type="info"
				showIcon
				message="Entries record what an authorized administrator was about to apply"
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

			<Table<AuditEntry>
				rowKey="_id"
				loading={loading}
				dataSource={page?.entries ?? []}
				columns={columns}
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
						load(filters, nextPage, nextSize);
					}
				}}
			/>
		</Space>
	);
}
