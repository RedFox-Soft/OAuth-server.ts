import { useEffect, useState } from 'react';
import {
	Alert,
	Button,
	Card,
	Col,
	Descriptions,
	Drawer,
	Empty,
	Input,
	Row,
	Select,
	Space,
	Modal,
	Statistic,
	Table,
	Tag,
	Typography
} from 'antd';

interface ErrorSample {
	reference: string;
	at: string;
	clientId: string | null;
	actor: { id: string; email: string } | null;
	scope: string | null;
	requestId: string | null;
	origin: string | null;
	userAgent: string | null;
	submittedFields: string[];
}

interface ErrorGroup {
	_id: string;
	fingerprint: string;
	errorCode: string;
	status: number;
	surface: string;
	route: string;
	method: string;
	origin: { file: string; line: number | null; frame: string };
	message: string;
	occurrences: number;
	firstSeenAt: string;
	lastSeenAt: string;
	samples: ErrorSample[];
}

interface ErrorPage {
	groups: ErrorGroup[];
	total: number;
	dropped: number;
	recording: boolean;
}

interface Bucket {
	key: string;
	count: number;
}

interface Summary {
	total: number;
	byErrorCode: Bucket[];
	byRoute: Bucket[];
	dropped: number;
	recording: boolean;
}

interface Filters {
	errorCode: string;
	route: string;
	surface: string;
	status: string;
	clientId: string;
	actor: string;
	from: string;
	to: string;
}

const EMPTY_FILTERS: Filters = {
	errorCode: '',
	route: '',
	surface: '',
	status: '',
	clientId: '',
	actor: '',
	from: '',
	to: ''
};

/*
 * Only non-empty filters are sent. An empty string is a filter the operator did not set, and sending it
 * would be a filter on the empty value — which matches nothing and would read as "no faults".
 */
function buildQuery(active: Filters, atPage: number, size: number): string {
	const params = new URLSearchParams();
	for (const [name, value] of Object.entries(active)) {
		if (value !== '') params.set(name, value);
	}
	params.set('limit', String(size));
	params.set('offset', String((atPage - 1) * size));
	return params.toString();
}

const SURFACE_COLOUR: Record<string, string> = {
	oauth: 'blue',
	admin: 'purple',
	mcp: 'geekblue',
	interaction: 'cyan'
};

export function Errors() {
	const [page, setPage] = useState<ErrorPage | null>(null);
	const [loading, setLoading] = useState(true);
	const [selected, setSelected] = useState<ErrorGroup | null>(null);
	const [current, setCurrent] = useState(1);
	const [pageSize, setPageSize] = useState(50);
	const [filters, setFilters] = useState<Filters>(EMPTY_FILTERS);
	const [summary, setSummary] = useState<Summary | null>(null);
	const [reference, setReference] = useState('');
	const [lookupError, setLookupError] = useState<string | null>(null);
	const [purgePreview, setPurgePreview] = useState<{
		groups: number;
		occurrences: number;
	} | null>(null);
	const [purging, setPurging] = useState(false);

	/*
	 * Two steps, and the first one is the point: an operator is shown what the current filters would
	 * destroy before anything is destroyed. The preview and the purge send the same filters to endpoints
	 * that share one query schema, so what is shown is what goes.
	 */
	async function previewPurge() {
		const params = new URLSearchParams();
		for (const [name, value] of Object.entries(filters)) {
			if (value !== '') params.set(name, value);
		}
		const res = await fetch(`/admin/api/errors/purge-preview?${params}`);
		if (res.ok) {
			setPurgePreview(
				(await res.json()) as { groups: number; occurrences: number }
			);
		}
	}

	async function confirmPurge() {
		setPurging(true);
		try {
			const params = new URLSearchParams();
			for (const [name, value] of Object.entries(filters)) {
				if (value !== '') params.set(name, value);
			}
			await fetch(`/admin/api/errors?${params}`, { method: 'DELETE' });
			setPurgePreview(null);
			load(filters, 1, pageSize);
			setCurrent(1);
		} finally {
			setPurging(false);
		}
	}

	/*
	 * A purge needs at least one filter — the API refuses an unfiltered one rather than treating it as
	 * "everything", and the button follows that rather than offering an action that can only fail.
	 */
	const canPurge = Object.values(filters).some((value) => value !== '');

	/*
	 * The support path: an integrator quotes a reference, and this lands on the one fault. Opens the same
	 * drawer the table does, so there is one way to read a fault however it was found.
	 */
	async function lookup() {
		setLookupError(null);
		const trimmed = reference.trim();
		if (trimmed === '') return;

		const res = await fetch(
			`/admin/api/errors/reference/${encodeURIComponent(trimmed)}`
		);
		if (res.ok) {
			const body = (await res.json()) as { group: ErrorGroup };
			setSelected(body.group);
			return;
		}
		// Said plainly rather than shown as an empty table: "no such record" is an answer, not a blank.
		setLookupError(
			res.status === 404
				? 'No fault carries that reference. It may be mistyped, from another deployment, or already aged out.'
				: 'That lookup could not be completed.'
		);
	}

	/*
	 * Filters are passed in rather than read from state, so a request always uses the values the caller
	 * meant — resetting and reloading in one action would otherwise send the state it just replaced.
	 */
	async function load(active: Filters, atPage: number, size: number) {
		setLoading(true);
		try {
			const res = await fetch(
				`/admin/api/errors?${buildQuery(active, atPage, size)}`
			);
			if (res.ok) setPage((await res.json()) as ErrorPage);

			/*
			 * The summary takes a window only, so it follows just the two date filters. Narrowing it by
			 * route would make the "worst endpoint" ranking answer about one endpoint, which is not a
			 * ranking.
			 */
			const window = new URLSearchParams();
			if (active.from !== '') window.set('from', active.from);
			if (active.to !== '') window.set('to', active.to);
			const sum = await fetch(`/admin/api/errors/summary?${window.toString()}`);
			if (sum.ok) setSummary((await sum.json()) as Summary);
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

	const set = (name: keyof Filters) => (value: string) =>
		setFilters((prev) => ({ ...prev, [name]: value }));

	const columns = [
		{
			title: 'Last seen',
			dataIndex: 'lastSeenAt',
			render: (value: string) => new Date(value).toLocaleString()
		},
		{
			title: 'Count',
			dataIndex: 'occurrences',
			/*
			 * Shown as a plain number and not abbreviated: the difference between 900 and 9,000 is the
			 * difference between a bug and an outage, and "9k" hides which one an operator is looking at.
			 */
			render: (value: number) => <strong>{value}</strong>
		},
		{
			title: 'Where',
			dataIndex: 'route',
			render: (route: string, row: ErrorGroup) => (
				<Space
					direction="vertical"
					size={0}
				>
					<Typography.Text code>
						{row.method} {route}
					</Typography.Text>
					<Tag color={SURFACE_COLOUR[row.surface] ?? 'default'}>
						{row.surface}
					</Tag>
				</Space>
			)
		},
		{
			title: 'Fault',
			dataIndex: 'message',
			render: (message: string, row: ErrorGroup) => (
				<Space
					direction="vertical"
					size={0}
				>
					<Typography.Text>{message}</Typography.Text>
					<Typography.Text type="secondary">
						{row.origin.file}
						{row.origin.line === null ? '' : `:${row.origin.line}`}
					</Typography.Text>
				</Space>
			)
		},
		{
			title: 'Status',
			dataIndex: 'status',
			render: (status: number, row: ErrorGroup) => (
				<Space
					direction="vertical"
					size={0}
				>
					<Tag color="red">{status}</Tag>
					<Typography.Text type="secondary">{row.errorCode}</Typography.Text>
				</Space>
			)
		}
	];

	return (
		<Card>
			<Space
				direction="vertical"
				style={{ width: '100%' }}
				size="middle"
			>
				<Typography.Title level={3}>Server faults</Typography.Title>
				<Typography.Paragraph type="secondary">
					Unexpected internal faults, one row per distinct fault. Routine client
					rejections are not recorded, so everything here is a defect.
				</Typography.Paragraph>

				{/*
				 * Stated rather than hidden. A non-zero drop count means this list is missing faults that
				 * really happened, and an operator reading an incomplete list as complete would draw the
				 * opposite conclusion from the evidence.
				 */}
				{page && page.recording === false ? (
					<Alert
						type="info"
						showIcon
						message="Fault recording is switched off"
						description="Nothing is being recorded, so an empty list here does not mean the server has had no faults. Switch it on under Settings → Error Store."
					/>
				) : null}

				{summary ? (
					<Row gutter={16}>
						<Col span={6}>
							<Card size="small">
								<Statistic
									title="Occurrences"
									value={summary.total}
								/>
							</Card>
						</Col>
						<Col span={9}>
							<Card
								size="small"
								title="Worst endpoints"
							>
								{/* Ranked by occurrences, so one loud fault outranks a quiet long tail. */}
								{summary.byRoute.slice(0, 5).map((bucket) => (
									<div key={bucket.key}>
										<Typography.Text code>{bucket.key}</Typography.Text>{' '}
										<Typography.Text strong>{bucket.count}</Typography.Text>
									</div>
								))}
								{summary.byRoute.length === 0 ? (
									<Typography.Text type="secondary">—</Typography.Text>
								) : null}
							</Card>
						</Col>
						<Col span={9}>
							<Card
								size="small"
								title="By error code"
							>
								{summary.byErrorCode.slice(0, 5).map((bucket) => (
									<div key={bucket.key}>
										<Typography.Text code>{bucket.key}</Typography.Text>{' '}
										<Typography.Text strong>{bucket.count}</Typography.Text>
									</div>
								))}
								{summary.byErrorCode.length === 0 ? (
									<Typography.Text type="secondary">—</Typography.Text>
								) : null}
							</Card>
						</Col>
					</Row>
				) : null}

				<Space wrap>
					<Input.Search
						placeholder="reference from a report (err_…)"
						style={{ width: 320 }}
						enterButton="Look up"
						value={reference}
						onChange={(e) => setReference(e.target.value)}
						onSearch={lookup}
					/>
				</Space>

				{lookupError ? (
					<Alert
						type="warning"
						showIcon
						message={lookupError}
						closable
					/>
				) : null}

				<Space wrap>
					<Input
						placeholder="endpoint"
						style={{ width: 200 }}
						value={filters.route}
						onChange={(e) => set('route')(e.target.value)}
					/>
					<Input
						placeholder="error code"
						style={{ width: 150 }}
						value={filters.errorCode}
						onChange={(e) => set('errorCode')(e.target.value)}
					/>
					<Select
						placeholder="surface"
						style={{ width: 140 }}
						allowClear
						value={filters.surface === '' ? undefined : filters.surface}
						options={['oauth', 'admin', 'mcp', 'interaction'].map((s) => ({
							label: s,
							value: s
						}))}
						onChange={(v) => set('surface')(v ?? '')}
					/>
					<Input
						placeholder="status"
						style={{ width: 110 }}
						value={filters.status}
						onChange={(e) => set('status')(e.target.value)}
					/>
					<Input
						placeholder="client id"
						style={{ width: 180 }}
						value={filters.clientId}
						onChange={(e) => set('clientId')(e.target.value)}
					/>
					<Input
						placeholder="actor id or email"
						style={{ width: 200 }}
						value={filters.actor}
						onChange={(e) => set('actor')(e.target.value)}
					/>
					<Input
						placeholder="from (ISO)"
						style={{ width: 190 }}
						value={filters.from}
						onChange={(e) => set('from')(e.target.value)}
					/>
					<Input
						placeholder="to (ISO)"
						style={{ width: 190 }}
						value={filters.to}
						onChange={(e) => set('to')(e.target.value)}
					/>
					<Button
						type="primary"
						onClick={apply}
					>
						Apply
					</Button>
					<Button onClick={reset}>Reset</Button>
					<Button
						danger
						disabled={!canPurge}
						onClick={previewPurge}
					>
						Purge matching…
					</Button>
				</Space>

				{!canPurge ? (
					<Typography.Text type="secondary">
						Purging requires at least one filter — there is deliberately no way
						to delete every record in one action.
					</Typography.Text>
				) : null}

				{page && page.dropped > 0 ? (
					<Alert
						type="warning"
						showIcon
						message={`${page.dropped} fault(s) could not be recorded`}
						description="Recording fell behind, so this list is incomplete. Raise the pending write queue depth in Settings, or investigate why the store is slow."
					/>
				) : null}

				<Table<ErrorGroup>
					rowKey="_id"
					loading={loading}
					columns={columns}
					dataSource={page?.groups ?? []}
					locale={{
						emptyText: <Empty description="No faults recorded" />
					}}
					onRow={(row) => ({ onClick: () => setSelected(row) })}
					pagination={{
						current,
						pageSize,
						total: page?.total ?? 0,
						showSizeChanger: true,
						onChange: (nextPage, nextSize) => {
							setCurrent(nextPage);
							setPageSize(nextSize);
							load(filters, nextPage, nextSize);
						}
					}}
				/>
			</Space>

			<Modal
				open={purgePreview !== null}
				title="Purge these recorded faults?"
				okText={
					purgePreview ? `Purge ${purgePreview.groups} fault(s)` : 'Purge'
				}
				okButtonProps={{ danger: true, loading: purging }}
				onOk={confirmPurge}
				onCancel={() => setPurgePreview(null)}
			>
				{purgePreview ? (
					<Space direction="vertical">
						<Typography.Text>
							{purgePreview.groups} distinct fault(s), covering{' '}
							{purgePreview.occurrences} occurrence(s), match the current
							filters.
						</Typography.Text>
						{/* Said plainly: this is the only account of what went wrong, and it does not come back. */}
						<Typography.Text type="danger">
							This cannot be undone. A purge is recorded in the audit trail.
						</Typography.Text>
					</Space>
				) : null}
			</Modal>

			<Drawer
				width={640}
				open={selected !== null}
				onClose={() => setSelected(null)}
				title={selected ? `${selected.method} ${selected.route}` : ''}
			>
				{selected ? (
					<Space
						direction="vertical"
						size="middle"
						style={{ width: '100%' }}
					>
						<Descriptions
							column={1}
							size="small"
							bordered
						>
							<Descriptions.Item label="Fault">
								{selected.message}
							</Descriptions.Item>
							<Descriptions.Item label="Origin">
								{selected.origin.frame} — {selected.origin.file}
								{selected.origin.line === null
									? ''
									: `:${selected.origin.line}`}
							</Descriptions.Item>
							<Descriptions.Item label="Occurrences">
								{selected.occurrences}
							</Descriptions.Item>
							<Descriptions.Item label="First seen">
								{new Date(selected.firstSeenAt).toLocaleString()}
							</Descriptions.Item>
							<Descriptions.Item label="Last seen">
								{new Date(selected.lastSeenAt).toLocaleString()}
							</Descriptions.Item>
						</Descriptions>

						<Typography.Text type="secondary">
							{/*
							 * Says what the sample list is, because a count of 900 beside 10 samples otherwise
							 * reads as data loss rather than as a deliberate bound.
							 */}
							Retained occurrences ({selected.samples.length} of{' '}
							{selected.occurrences}) — the earliest, plus the most recent.
						</Typography.Text>

						{selected.samples.map((sample) => (
							<Descriptions
								key={sample.reference}
								column={1}
								size="small"
								bordered
							>
								<Descriptions.Item label="Reference">
									<Typography.Text
										copyable
										code
									>
										{sample.reference}
									</Typography.Text>
								</Descriptions.Item>
								<Descriptions.Item label="At">
									{new Date(sample.at).toLocaleString()}
								</Descriptions.Item>
								<Descriptions.Item label="Client">
									{sample.clientId ?? '—'}
								</Descriptions.Item>
								<Descriptions.Item label="Actor">
									{sample.actor?.email ?? '—'}
								</Descriptions.Item>
								<Descriptions.Item label="Origin">
									{sample.origin === 'not-captured'
										? 'not captured'
										: (sample.origin ?? '—')}
								</Descriptions.Item>
								<Descriptions.Item label="User agent">
									{sample.userAgent ?? '—'}
								</Descriptions.Item>
								<Descriptions.Item label="Fields submitted">
									{/* Names only — no value a request carried is ever stored. */}
									{sample.submittedFields.length
										? sample.submittedFields.map((field) => (
												<Tag key={field}>{field}</Tag>
											))
										: '—'}
								</Descriptions.Item>
							</Descriptions>
						))}
					</Space>
				) : null}
			</Drawer>
		</Card>
	);
}
