import { useCallback, useEffect, useState } from 'react';
import { Card, Descriptions, Tag, Typography } from 'antd';
import { request } from '../frame/request.js';
import { LoadFailed } from '../frame/states.js';

type FactsWord = 'off' | 'not-yet' | 'current' | 'stale';

export interface NetworkFactsView {
	enabled: boolean;
	state: FactsWord;
	held: {
		fullVersion: string;
		deltaVersion: string | null;
		builtAt: string;
		ageSeconds: number;
		ranges: number;
	} | null;
	lastCheckAt: string | null;
	lastAcceptedAt: string | null;
	lastProblem: { kind: string; at: string; consecutive: number } | null;
	unreadableReads: number;
	scope: 'process';
}

const STATE: Record<FactsWord, { tag: string; color: string; line: string }> = {
	off: {
		tag: 'off',
		color: 'default',
		line: 'Off. Nothing is downloaded, and every path with a network facts condition is closed.'
	},
	'not-yet': {
		tag: 'loading',
		color: 'blue',
		line: 'On, and not loaded yet. Paths with a network facts condition stay closed until it is.'
	},
	current: {
		tag: 'current',
		color: 'green',
		line: 'Current: conditions at the proxy are judged on it.'
	},
	stale: {
		tag: 'out of date',
		color: 'red',
		line: 'More than 26 hours old: network facts are unknown, and every path with a network facts condition is closed until a fresh snapshot loads.'
	}
};

const PROBLEM: Record<string, string> = {
	signature: 'a file did not carry FoxTrust’s signature, twice in a row',
	digest: 'a file did not match the published digest, twice in a row',
	size: 'a file was larger than allowed or not the published size',
	header: 'the published list of files could not be read',
	older: 'FoxTrust offered data older than the data already accepted',
	format: 'a file is not a kind this FoxAuth can read; update FoxAuth',
	base: 'an hourly update was made for another daily file; the daily file is used alone until the next one',
	network: 'FoxTrust could not be reached',
	http: 'FoxTrust answered with an error'
};

function age(seconds: number): string {
	if (seconds < 3600) return `${String(Math.floor(seconds / 60))} minutes`;
	return `${String(Math.floor(seconds / 3600))} hours ${String(Math.floor((seconds % 3600) / 60))} minutes`;
}

/*
 * FoxTrust's network facts on this server (specs/129), under the `networkFacts.enabled` switch. Read-only: the switch
 * is an ordinary setting. What it shows is the answering server process's copy.
 */
export function NetworkFactsCard() {
	const [loading, setLoading] = useState(true);
	const [view, setView] = useState<NetworkFactsView | null>(null);
	const [failed, setFailed] = useState<string | null>(null);

	const load = useCallback(async () => {
		try {
			const result = await request<NetworkFactsView>(
				'GET',
				'/admin/api/settings/network-facts'
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
	useEffect(() => {
		void load();
	}, [load]);

	const state = view ? STATE[view.state] : null;
	return (
		<Card
			title="Network facts from FoxTrust"
			size="small"
			style={{ marginBottom: 16 }}
			loading={loading}
			extra={state ? <Tag color={state.color}>{state.tag}</Tag> : null}
		>
			{failed !== null ? (
				<LoadFailed
					reason={failed}
					onRetry={() => {
						setLoading(true);
						void load();
					}}
				/>
			) : view && state ? (
				<>
					<Descriptions
						size="small"
						column={1}
						style={{ marginBottom: 12 }}
						items={[
							{ key: 'state', label: 'State', children: state.line },
							...(view.held
								? [
										{
											key: 'version',
											label: 'Snapshot',
											children: view.held.deltaVersion
												? `${view.held.fullVersion}, updated ${view.held.deltaVersion}`
												: view.held.fullVersion
										},
										{
											key: 'built',
											label: 'Built',
											children: `${new Date(view.held.builtAt).toLocaleString()} (${age(view.held.ageSeconds)} ago)`
										},
										{
											key: 'ranges',
											label: 'Address ranges',
											children: view.held.ranges.toLocaleString()
										}
									]
								: []),
							{
								key: 'checked',
								label: 'Last checked',
								children: view.lastCheckAt
									? new Date(view.lastCheckAt).toLocaleString()
									: 'Not yet'
							},
							...(view.lastProblem
								? [
										{
											key: 'problem',
											label: 'Last problem',
											children: `${PROBLEM[view.lastProblem.kind] ?? view.lastProblem.kind} (${new Date(view.lastProblem.at).toLocaleString()}). The snapshot already held stays in use until it is 26 hours old.`
										}
									]
								: []),
							...(view.unreadableReads > 0
								? [
										{
											key: 'unreadable',
											label: 'Unreadable records',
											children: `${String(view.unreadableReads)} lookups met a record this FoxAuth could not read; those addresses were treated as unknown.`
										}
									]
								: [])
						]}
					/>
					<Typography.Paragraph
						type="secondary"
						style={{ margin: 0 }}
					>
						This server downloads FoxTrust&apos;s signed snapshot of what is
						known about internet addresses: a full file once a day (about 13 MB)
						and an update every hour, each checked against FoxTrust&apos;s
						signature before use. Addresses of people are looked up here and
						never sent; FoxTrust learns only that the file was downloaded.
						Countries: IP Geolocation by DB-IP (CC BY 4.0). Shown for the server
						process that answered.
					</Typography.Paragraph>
				</>
			) : null}
		</Card>
	);
}
