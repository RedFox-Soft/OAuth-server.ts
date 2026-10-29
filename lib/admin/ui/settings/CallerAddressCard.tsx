import { useCallback, useEffect, useState } from 'react';
import { Alert, Card, Descriptions, Typography } from 'antd';
import { request } from '../frame/request.js';
import { LoadFailed } from '../frame/states.js';

type Warning =
	'fly-header-missing' | 'forwarded-ignored' | 'fly-header-present';

interface CallerAddressView {
	source: string;
	attributed: {
		address: string;
		from: 'connection' | 'x-forwarded-for' | 'fly-client-ip' | 'unattributed';
	};
	connection: string | null;
	forwardedHeaders: string[];
	warning: Warning | null;
}

const FROM: Record<CallerAddressView['attributed']['from'], string> = {
	connection: 'the connection itself',
	'x-forwarded-for': 'X-Forwarded-For, the part your proxy wrote',
	'fly-client-ip': 'Fly-Client-IP, set by Fly’s edge',
	unattributed: 'nowhere: this request has no connection'
};

const WARNING: Record<Warning, string> = {
	'fly-header-missing':
		'“fly” is chosen, but this request did not come through Fly’s edge. A caller behind your proxy could write Fly-Client-IP itself and escape every limit. Choose “automatic”, or the choice that matches your proxy.',
	'fly-header-present':
		'This request came through Fly’s edge, but “fly” is not chosen. On Fly every caller would share one address and be refused together. Choose “fly”.',
	'forwarded-ignored':
		'Proxy headers arrived on a connection this choice does not trust, so every caller looks like that proxy and shares one allowance. Choose the option that matches your proxy, or list its address.'
};

/*
 * What the server sees for the person looking at it (specs/115, FR-008). The choice above has a wrong
 * answer in each direction and both look like a working server, so the only check an operator has is
 * their own request: the address they know is theirs, and where the server found it.
 */
export function CallerAddressCard() {
	const [loading, setLoading] = useState(true);
	const [view, setView] = useState<CallerAddressView | null>(null);
	const [failed, setFailed] = useState<string | null>(null);

	const load = useCallback(async () => {
		try {
			const result = await request<CallerAddressView>(
				'GET',
				'/admin/api/settings/client-address'
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
			title="The address this server sees for you"
			size="small"
			style={{ marginBottom: 16 }}
			loading={loading}
		>
			{failed !== null ? (
				<LoadFailed
					reason={failed}
					onRetry={reload}
				/>
			) : view ? (
				<>
					{view.warning ? (
						<Alert
							type="warning"
							showIcon
							style={{ marginBottom: 12 }}
							title={WARNING[view.warning]}
						/>
					) : null}
					<Descriptions
						size="small"
						column={1}
						items={[
							{
								key: 'address',
								label: 'Your address',
								children: (
									<Typography.Text code>
										{view.attributed.address}
									</Typography.Text>
								)
							},
							{
								key: 'from',
								label: 'Taken from',
								children: FROM[view.attributed.from]
							},
							{
								key: 'connection',
								label: 'Connection from',
								children: view.connection ?? 'none'
							},
							{
								key: 'headers',
								label: 'Proxy headers received',
								children: view.forwardedHeaders.length
									? view.forwardedHeaders.join(', ')
									: 'none'
							}
						]}
					/>
					<Typography.Paragraph
						type="secondary"
						style={{ marginTop: 12, marginBottom: 0 }}
					>
						If “Your address” is not the address you are connecting from, every
						limit is counting the wrong caller. Compare it with any “what is my
						IP” page.
					</Typography.Paragraph>
				</>
			) : null}
		</Card>
	);
}
