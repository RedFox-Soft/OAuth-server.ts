import { useCallback, useEffect, useState } from 'react';
import { Card, Descriptions, Tag, Typography } from 'antd';
import { request } from '../frame/request.js';
import { LoadFailed } from '../frame/states.js';

type LookupWord =
	'off' | 'key-unreadable' | 'on' | 'stopped' | 'reporting-off' | 'waiting';

type Answer =
	| 'key'
	| 'not_yet'
	| 'muted'
	| 'key_mismatch'
	| 'invalid'
	| 'limited'
	| 'unavailable'
	| 'unreachable';

export interface AddressLookupView {
	setting: boolean;
	state: LookupWord;
	instanceId: string;
	instanceKey: string | null;
	key: { receivedAt: string; dailyQuota: number; burst: number } | null;
	today: {
		day: string;
		limit: number | null;
		remaining: number | null;
		usedUp: boolean;
	} | null;
	registration: {
		firstKeyReportAt: string | null;
		lastTriedAt: string | null;
		lastAnswer: Answer | null;
		lastInvalidField: string | null;
		nextTryAfter: string | null;
	};
	stopped: 'muted' | 'key_mismatch' | null;
}

const TAG: Record<LookupWord, { tag: string; color: string }> = {
	on: { tag: 'on', color: 'green' },
	off: { tag: 'off', color: 'default' },
	waiting: { tag: 'no key yet', color: 'blue' },
	'reporting-off': { tag: 'no key', color: 'gold' },
	stopped: { tag: 'stopped', color: 'red' },
	'key-unreadable': { tag: 'key unreadable', color: 'red' }
};

function date(iso: string): string {
	return new Date(iso).toLocaleDateString();
}

/* What the card says (specs/136 contracts/console.md §2): one line, the state and what to do about it. */
function stateLine(view: AddressLookupView): string {
	const next = view.registration.nextTryAfter;
	switch (view.state) {
		case 'on': {
			const today = view.today;
			const used =
				today && today.limit !== null && today.remaining !== null
					? ` ${String(today.limit - today.remaining)} of ${String(today.limit)} lookups used today.`
					: '';
			const usedUp = today?.usedUp ? ' Used up until midnight UTC.' : '';
			return `FoxTrust key held since ${date(view.key?.receivedAt ?? '')}.${used}${usedUp}`;
		}
		case 'off':
			return view.key
				? 'Turned off. Nothing is looked up or asked for. The key already received is kept.'
				: 'Turned off. Nothing is looked up or asked for.';
		case 'reporting-off':
			return 'No key can come while usage reporting is off: FoxTrust issues one only to a server whose reports it has seen for a week.';
		case 'key-unreadable':
			return 'The instance key cannot be read: the keyring that sealed it is not loaded. Load that keyring; a new key pair is never made.';
		case 'stopped':
			return view.stopped === 'key_mismatch'
				? 'FoxTrust knows this instance id with another instance key, for example from a database restored without its keyring. Contact FoxTrust support with the instance id and key below.'
				: 'FoxTrust has stopped issuing keys to this server. Contact FoxTrust support with the instance id and key below.';
		case 'waiting': {
			const when = next ? date(next) : null;
			switch (view.registration.lastAnswer) {
				case 'not_yet':
					return `FoxTrust has not issued a key yet. Next try: ${when ?? 'soon'}.`;
				case 'invalid':
					return `FoxTrust refused the last request (${view.registration.lastInvalidField ?? 'no reason given'}). Next try: ${when ?? 'soon'}.`;
				case 'limited':
				case 'unavailable':
				case 'unreachable':
					return `FoxTrust could not be reached or was busy. Next try: ${when ?? 'soon'}.`;
				default:
					return when
						? `No key yet. This server asks FoxTrust for one on ${when}, a week after its first usage report with its instance key.`
						: 'No key yet. This server asks FoxTrust for one a week after its first usage report with its instance key is delivered.';
			}
		}
	}
}

/*
 * Whether this server can look up the network owner and location of people's addresses (specs/136), under the
 * `addressLookup.enabled` switch. Read-only: the switch is an ordinary setting, and there is no button, because only
 * FoxTrust can change what a refusal says.
 */
export function AddressLookupCard() {
	const [loading, setLoading] = useState(true);
	const [view, setView] = useState<AddressLookupView | null>(null);
	const [failed, setFailed] = useState<string | null>(null);

	const load = useCallback(async () => {
		try {
			const result = await request<AddressLookupView>(
				'GET',
				'/admin/api/settings/address-lookup'
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

	const tag = view ? TAG[view.state] : null;
	return (
		<Card
			title="Network owner and location"
			size="small"
			style={{ marginBottom: 16 }}
			loading={loading}
			extra={tag ? <Tag color={tag.color}>{tag.tag}</Tag> : null}
		>
			{failed !== null ? (
				<LoadFailed
					reason={failed}
					onRetry={() => {
						setLoading(true);
						void load();
					}}
				/>
			) : view ? (
				<>
					<Descriptions
						size="small"
						column={1}
						style={{ marginBottom: 12 }}
						items={[
							{ key: 'state', label: 'State', children: stateLine(view) },
							{
								key: 'id',
								label: 'Instance id',
								children: (
									<Typography.Text
										code
										copyable
									>
										{view.instanceId}
									</Typography.Text>
								)
							},
							{
								key: 'key',
								label: 'Instance key',
								children: view.instanceKey ? (
									<Typography.Text
										code
										copyable
									>
										{view.instanceKey}
									</Typography.Text>
								) : (
									'Cannot be read'
								)
							}
						]}
					/>
					<Typography.Paragraph
						type="secondary"
						style={{ margin: 0 }}
					>
						The addresses people&apos;s activity records are looked up at
						FoxTrust&apos;s API, in batches, with this server&apos;s key and
						nothing about the person. FoxTrust keeps none of them and acts as
						your processor under its terms (foxtrust.dev/terms). The instance
						key is public: it is what FoxTrust knows this server by.
					</Typography.Paragraph>
				</>
			) : null}
		</Card>
	);
}
