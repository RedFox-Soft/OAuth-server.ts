import { useCallback, useEffect, useState } from 'react';
import { Card, Descriptions, Table, Tag, Typography } from 'antd';
import { request } from '../frame/request.js';
import { LoadFailed } from '../frame/states.js';
import {
	ATTACK_TYPES,
	PROBE_PATHS
} from '../../../consts/attack_report_fields.js';

interface AttackReportsView {
	enabled: boolean;
	offBecause?: 'setting' | 'no-datastore';
	setting: boolean;
	lastDeliveredAt: string | null;
	report: unknown;
	reportIsPreview: boolean;
}

const OFF_REASON: Record<
	NonNullable<AttackReportsView['offBecause']>,
	string
> = {
	setting: 'turned off by the setting above',
	'no-datastore': 'this server has no database, so it never reports'
};

const TYPE_ROWS = ATTACK_TYPES.map((type) => ({
	key: type.name,
	name: type.name,
	threshold: type.threshold,
	meaning: type.meaning,
	notCounted: type.notCounted
}));

const PROBE_ROWS = PROBE_PATHS.map((probe) => ({
	key: probe.label,
	label: probe.label,
	paths: [...probe.exact, ...probe.prefixes.map((prefix) => `${prefix}…`)].join(
		', '
	)
}));

/*
 * What this server tells FoxTrust about the addresses that attack it (specs/114, FR-022).
 *
 * Read-only: the switch is the ordinary `attackReports.enabled` setting above it. A delivery that did not
 * happen is shown as a time, never in error styling (FR-023). The two tables come from the same declaration
 * the report is built from (FR-017), so what the operator reads here is what can leave.
 */
export function AttackReportsCard() {
	const [loading, setLoading] = useState(true);
	const [view, setView] = useState<AttackReportsView | null>(null);
	const [failed, setFailed] = useState<string | null>(null);

	const load = useCallback(async () => {
		try {
			const result = await request<AttackReportsView>(
				'GET',
				'/admin/api/settings/attack-reports'
			);
			if (!result.ok) {
				setFailed(result.error.message);
				return;
			}
			setFailed(null);
			setView(result.data);
		} finally {
			setLoading(false);
		}
	}, []);
	function reload() {
		setLoading(true);
		void load();
	}
	useEffect(() => {
		void load();
	}, [load]);

	return (
		<Card
			title="What attack reporting sends"
			size="small"
			style={{ marginBottom: 16 }}
			loading={loading}
			extra={
				view ? (
					<Tag color={view.enabled ? 'green' : 'default'}>
						{view.enabled ? 'reporting' : 'off'}
					</Tag>
				) : null
			}
		>
			{failed !== null ? (
				<LoadFailed
					reason={failed}
					onRetry={reload}
				/>
			) : view ? (
				<>
					<Descriptions
						size="small"
						column={1}
						style={{ marginBottom: 12 }}
						items={[
							{
								key: 'state',
								label: 'State',
								children: view.enabled
									? 'On: at most one report an hour, only when an address crossed a threshold'
									: `Off: ${view.offBecause ? OFF_REASON[view.offBecause] : 'turned off'}`
							},
							{
								key: 'delivered',
								label: 'Last delivered',
								children: view.lastDeliveredAt
									? new Date(view.lastDeliveredAt).toLocaleString()
									: 'Never delivered'
							}
						]}
					/>
					<Typography.Text strong>
						{view.reportIsPreview
							? 'Example of a report (no real addresses)'
							: 'Last report sent'}
					</Typography.Text>
					<pre
						style={{
							margin: '8px 0 16px',
							maxHeight: 360,
							overflow: 'auto',
							fontSize: 12,
							whiteSpace: 'pre-wrap',
							wordBreak: 'break-word'
						}}
					>
						{JSON.stringify(view.report, null, 2)}
					</pre>
					<Typography.Text strong>What counts as an attack</Typography.Text>
					<Table
						size="small"
						pagination={false}
						style={{ margin: '8px 0 16px' }}
						dataSource={TYPE_ROWS}
						columns={[
							{ title: 'Type', dataIndex: 'name' },
							{ title: 'Reported at', dataIndex: 'threshold' },
							{ title: 'What counts', dataIndex: 'meaning' },
							{ title: 'What does not', dataIndex: 'notCounted' }
						]}
					/>
					<Typography.Text strong>Scanner paths</Typography.Text>
					<Table
						size="small"
						pagination={false}
						style={{ margin: '8px 0 0' }}
						dataSource={PROBE_ROWS}
						columns={[
							{ title: 'Label', dataIndex: 'label' },
							{ title: 'Paths', dataIndex: 'paths' }
						]}
					/>
					<Typography.Paragraph
						type="secondary"
						style={{ margin: '8px 0 0' }}
					>
						Thresholds count one hour of one server process. Only public
						internet addresses are sent, an IPv6 address only as its /64
						network, and nothing the caller sent.{' '}
						<a
							href="https://foxauth.dev/docs/reference/attack-reports/"
							target="_blank"
							rel="noreferrer"
						>
							Every field explained
						</a>
					</Typography.Paragraph>
				</>
			) : null}
		</Card>
	);
}
