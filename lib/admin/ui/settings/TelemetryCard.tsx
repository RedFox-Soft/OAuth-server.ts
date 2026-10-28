import { useCallback, useEffect, useState } from 'react';
import { Card, Descriptions, Tag, Typography } from 'antd';
import { request } from '../frame/request.js';
import { LoadFailed } from '../frame/states.js';

interface TelemetryView {
	enabled: boolean;
	offBecause?: 'setting' | 'no-datastore';
	setting: boolean;
	instanceId: string;
	lastDeliveredAt: string | null;
	report: unknown;
	reportIsPreview: boolean;
	nextReportAfter: string | null;
}

const OFF_REASON: Record<NonNullable<TelemetryView['offBecause']>, string> = {
	setting: 'turned off by the setting above',
	'no-datastore': 'this server has no database, so it never reports'
};

/*
 * What this server tells the maintainers, shown before anyone has to ask (specs/113, FR-019).
 *
 * Read-only: the switch is the ordinary `telemetry.enabled` setting in the card above it, saved with the
 * rest. A delivery that did not happen is shown as a time, never in error styling (FR-020) — a server
 * without a route to the internet is working as intended, and an operator should not be taught to worry
 * about it.
 */
export function TelemetryCard() {
	const [loading, setLoading] = useState(true);
	const [view, setView] = useState<TelemetryView | null>(null);
	const [failed, setFailed] = useState<string | null>(null);

	const load = useCallback(async () => {
		try {
			const result = await request<TelemetryView>(
				'GET',
				'/admin/api/settings/telemetry'
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
			title="What usage reporting sends"
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
									? 'On: one report a day'
									: `Off: ${view.offBecause ? OFF_REASON[view.offBecause] : 'turned off'}`
							},
							{
								key: 'instance',
								label: 'Instance identifier',
								children: (
									<Typography.Text code>{view.instanceId}</Typography.Text>
								)
							},
							{
								key: 'delivered',
								label: 'Last delivered',
								children: view.lastDeliveredAt
									? new Date(view.lastDeliveredAt).toLocaleString()
									: 'Never delivered'
							},
							...(view.nextReportAfter
								? [
										{
											key: 'next',
											label: 'Next report',
											children: new Date(view.nextReportAfter).toLocaleString()
										}
									]
								: [])
						]}
					/>
					<Typography.Text strong>
						{view.reportIsPreview
							? 'Next report (preview)'
							: 'Last report sent'}
					</Typography.Text>
					<pre
						style={{
							margin: '8px 0 0',
							maxHeight: 360,
							overflow: 'auto',
							fontSize: 12,
							whiteSpace: 'pre-wrap',
							wordBreak: 'break-word'
						}}
					>
						{JSON.stringify(view.report, null, 2)}
					</pre>
					<Typography.Paragraph
						type="secondary"
						style={{ margin: '8px 0 0' }}
					>
						The identifier is random and derived from nothing about this server.
						No name, email, hostname, address or setting value is ever sent.{' '}
						<a
							href="https://foxauth.dev/docs/reference/telemetry/"
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
