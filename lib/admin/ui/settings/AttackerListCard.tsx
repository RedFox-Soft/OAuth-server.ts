import { useCallback, useEffect, useState } from 'react';
import { Card, Descriptions, Tag, Typography } from 'antd';
import { request } from '../frame/request.js';
import { LoadFailed } from '../frame/states.js';

type ListWord =
	'off' | 'not-yet' | 'current' | 'out-of-date' | 'unknown-format';

export interface AttackerListView {
	enabled: boolean;
	effective: boolean;
	state: ListWord;
	held: {
		version: string;
		builtAt: string;
		validUntil: string;
		entries: number;
	} | null;
	lastCheckAt: string | null;
	lastAcceptedAt: string | null;
	lastProblem: { kind: string; at: string; consecutive: number } | null;
	scope: 'process';
	projectsUsing: { count: number; refuse: number };
}

const STATE: Record<ListWord, { tag: string; color: string; line: string }> = {
	off: {
		tag: 'off',
		color: 'default',
		line: 'Off. Nothing is downloaded, counted or refused.'
	},
	'not-yet': {
		tag: 'waiting',
		color: 'blue',
		line: 'On, and not downloaded yet. Nothing is counted or refused until it is.'
	},
	current: {
		tag: 'current',
		color: 'green',
		line: 'Current: projects count or refuse with it as each one chooses.'
	},
	'out-of-date': {
		tag: 'out of date',
		color: 'orange',
		line: 'Out of date: no newer list could be downloaded, so nobody is refused because of it.'
	},
	'unknown-format': {
		tag: 'update FoxAuth',
		color: 'orange',
		line: 'FoxTrust publishes a format this FoxAuth cannot read. Update FoxAuth; until then nobody is refused because of the list.'
	}
};

const PROBLEM: Record<string, string> = {
	signature: 'a file did not carry FoxTrust’s signature, twice in a row',
	digest: 'a file did not match the published digest, twice in a row',
	size: 'a file was larger than allowed or not the published size',
	header: 'a file did not describe itself as the list',
	older: 'FoxTrust offered a list older than the one already accepted',
	expired: 'FoxTrust offered a list already past its validity',
	format: 'FoxTrust lists only a format this FoxAuth cannot read',
	network: 'FoxTrust could not be reached',
	http: 'FoxTrust answered with an error'
};

/*
 * FoxTrust's attacker list on this server (specs/125), under its switch in Attack reporting. Read-only: the switch is
 * the ordinary `attackerList.enabled` setting, offered only while attack reporting is on. What it shows is the
 * answering server process's copy, and never an address.
 */
export function AttackerListCard() {
	const [loading, setLoading] = useState(true);
	const [view, setView] = useState<AttackerListView | null>(null);
	const [failed, setFailed] = useState<string | null>(null);

	const load = useCallback(async () => {
		try {
			const result = await request<AttackerListView>(
				'GET',
				'/admin/api/settings/attacker-list'
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
			title="FoxTrust's list of password-guessing addresses"
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
											key: 'built',
											label: 'List built',
											children: new Date(view.held.builtAt).toLocaleString()
										},
										{
											key: 'valid',
											label: 'Used until',
											children: new Date(view.held.validUntil).toLocaleString()
										},
										{
											key: 'entries',
											label: 'Addresses',
											children: view.held.entries
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
											children: `${PROBLEM[view.lastProblem.kind] ?? view.lastProblem.kind} (${new Date(view.lastProblem.at).toLocaleString()}). The list already held stays in use until it expires.`
										}
									]
								: []),
							{
								key: 'projects',
								label: 'Projects using it',
								children: `${String(view.projectsUsing.count)} count, ${String(view.projectsUsing.refuse)} of them refuse`
							}
						]}
					/>
					<Typography.Paragraph
						type="secondary"
						style={{ margin: 0 }}
					>
						Every hour this server downloads the addresses FoxTrust saw guessing
						passwords in the last 7 days and checks FoxTrust&apos;s signature
						before using them. FoxTrust learns nothing about who signs in here;
						the download names only FoxAuth and, while usage reporting is on,
						its version. Each project chooses what to do on its Sign-in tab.
						Shown for the server process that answered.
					</Typography.Paragraph>
				</>
			) : null}
		</Card>
	);
}
