import { useEffect, useState } from 'react';
import {
	Alert,
	Button,
	Card,
	Descriptions,
	Flex,
	Input,
	Radio,
	Space,
	Table,
	Typography
} from 'antd';
import { request } from '../../frame/request.js';
import { LoadFailed } from '../../frame/states.js';
import { useSignInSave } from './useSignInSave.js';

/*
 * What this project does with FoxTrust's list of addresses seen guessing passwords (specs/125), on its Sign-in tab.
 *
 * Its own card with its own save, beside the tab's draft rather than inside it: the numbers it shows are read live,
 * and choosing Refuse is consented to through the server's preview with those numbers, which the tab's save bar
 * would mix with unrelated changes. Never shows an address from the list; "Your address now" is the reader's own.
 */

type Mode = 'nothing' | 'count' | 'refuse';
type ListWord =
	'off' | 'not-yet' | 'current' | 'out-of-date' | 'unknown-format';

interface Exemption {
	network: string;
	until?: string;
}

interface GuessingView {
	mode: Mode;
	modeIsDefault: boolean;
	exempt: Exemption[];
	list: ListWord;
	days: number;
	counts: {
		listedAttempts: number;
		listedRightPassword: number;
		refused: number;
	};
	refuseAvailable: boolean;
	yourAddress: string | null;
}

const MODES: { value: Mode; label: string; effect: string }[] = [
	{
		value: 'nothing',
		label: 'Nothing',
		effect: 'Sign-ins from listed addresses are neither counted nor refused.'
	},
	{
		value: 'count',
		label: 'Count only',
		effect:
			'Nothing changes for anyone. The numbers below show how often listed addresses sign in here, so you can decide.'
	},
	{
		value: 'refuse',
		label: 'Refuse password sign-in',
		effect:
			'A listed address is refused once it has failed 3 passwords on this server within an hour, or at once when FoxTrust confirms it from independent sources. The person sees why, a line to send you, and the other ways to sign in.'
	}
];

const LIST_LINES: Record<Exclude<ListWord, 'current'>, string> = {
	off: "Off on this server: a super administrator turns on FoxTrust's list in Settings → Integrations. Until then nothing is counted or refused.",
	'not-yet':
		'The list has not been downloaded yet. Nothing is counted or refused until it is.',
	'out-of-date': 'The list is out of date, so nobody is refused because of it.',
	'unknown-format':
		'FoxTrust now publishes a format this FoxAuth cannot read. Update FoxAuth; until then nobody is refused because of the list.'
};

const sameExempt = (a: readonly Exemption[], b: readonly Exemption[]) =>
	JSON.stringify(a) === JSON.stringify(b);

export function PasswordGuessingCard({
	bucketId,
	bucketName,
	editable
}: {
	bucketId: string;
	bucketName: string;
	editable: boolean;
}) {
	const send = useSignInSave(bucketId, bucketName);
	const [view, setView] = useState<GuessingView | null>(null);
	const [failed, setFailed] = useState<string | null>(null);
	const [mode, setMode] = useState<Mode>('count');
	const [exempt, setExempt] = useState<Exemption[]>([]);
	const [network, setNetwork] = useState('');
	const [until, setUntil] = useState('');
	const [saving, setSaving] = useState(false);
	const [refusal, setRefusal] = useState<string | null>(null);

	const [reads, setReads] = useState(0);
	const reload = () => setReads((n) => n + 1);

	useEffect(() => {
		let live = true;
		void request<GuessingView>(
			'GET',
			`/admin/api/projects/${encodeURIComponent(bucketId)}/password-guessing`
		).then((result) => {
			if (!live) return;
			if (!result.ok) {
				setFailed(result.error.message);
				return;
			}
			setFailed(null);
			setView(result.data);
			setMode(result.data.mode);
			setExempt(result.data.exempt);
		});
		return () => {
			live = false;
		};
	}, [bucketId, reads]);

	if (failed !== null) {
		return (
			<Card title="Password guessing from known addresses">
				<LoadFailed
					reason={failed}
					onRetry={reload}
				/>
			</Card>
		);
	}
	if (!view)
		return (
			<Card
				title="Password guessing from known addresses"
				loading
			/>
		);

	const changed = mode !== view.mode || !sameExempt(exempt, view.exempt);

	function add() {
		const trimmed = network.trim();
		if (trimmed === '') return;
		setExempt([
			...exempt,
			until === ''
				? { network: trimmed }
				: {
						network: trimmed,
						until: new Date(`${until}T00:00:00Z`).toISOString()
					}
		]);
		setNetwork('');
		setUntil('');
	}

	async function save() {
		setSaving(true);
		setRefusal(null);
		try {
			const outcome = await send({ passwordGuessing: { mode, exempt } });
			if (outcome.kind === 'saved') reload();
			else if (outcome.kind === 'refused') setRefusal(outcome.message);
		} finally {
			setSaving(false);
		}
	}

	return (
		<Card title="Password guessing from known addresses">
			<Flex
				vertical
				gap={16}
			>
				<Typography.Text type="secondary">
					FoxTrust, the reputation service that receives this server&apos;s
					attack reports, publishes the addresses it saw guessing passwords in
					the last 7 days. FoxTrust never learns who signs in here. Only
					password sign-in is affected; sign-in through an identity provider,
					password reset and sign-up never are.
				</Typography.Text>
				{view.list !== 'current' && (
					<Alert
						type={view.list === 'off' ? 'info' : 'warning'}
						showIcon
						title={LIST_LINES[view.list]}
					/>
				)}
				<Radio.Group
					value={mode}
					disabled={!editable}
					onChange={(event) => setMode(event.target.value as Mode)}
				>
					<Space orientation="vertical">
						{MODES.filter(
							(m) => m.value !== 'refuse' || view.refuseAvailable
						).map((m) => (
							<Radio
								key={m.value}
								value={m.value}
							>
								<Typography.Text strong>
									{m.label}
									{m.value === 'count' ? ' (default)' : ''}
								</Typography.Text>
								<br />
								<Typography.Text type="secondary">{m.effect}</Typography.Text>
							</Radio>
						))}
					</Space>
				</Radio.Group>
				{!view.refuseAvailable && (
					<Typography.Text type="secondary">
						Refusing is not offered for the administrators&apos; project: it
						could lock every administrator out of this console.
					</Typography.Text>
				)}
				<Descriptions
					size="small"
					column={1}
					title={`Last ${String(view.days)} days`}
					items={[
						{
							key: 'attempts',
							label: 'Password sign-ins from listed addresses',
							children: view.counts.listedAttempts
						},
						{
							key: 'right',
							label: 'Of those, with the right password',
							children: view.counts.listedRightPassword
						},
						{
							key: 'refused',
							label: 'Refused because of the list',
							children: view.counts.refused
						}
					]}
				/>
				<Typography.Text strong>Never check these networks</Typography.Text>
				<Typography.Text type="secondary">
					An office, or a person who sent you the line from the refusal page. A
					single address or a range, optionally until a date.
				</Typography.Text>
				{exempt.length > 0 && (
					<Table
						size="small"
						pagination={false}
						rowKey={(row) => `${row.network}-${row.until ?? ''}`}
						dataSource={exempt}
						columns={[
							{ title: 'Network', dataIndex: 'network' },
							{
								title: 'Until',
								dataIndex: 'until',
								render: (value?: string) =>
									value ? new Date(value).toLocaleDateString() : 'No end'
							},
							{
								title: '',
								key: 'remove',
								render: (_: unknown, row: Exemption) =>
									editable ? (
										<Button
											size="small"
											onClick={() =>
												setExempt(exempt.filter((entry) => entry !== row))
											}
										>
											Remove
										</Button>
									) : null
							}
						]}
					/>
				)}
				{editable && (
					<Space.Compact style={{ width: '100%' }}>
						<Input
							aria-label="Network to exempt"
							placeholder="203.0.113.7 or 198.51.100.0/24"
							value={network}
							onChange={(event) => setNetwork(event.target.value)}
						/>
						<Input
							aria-label="Exempt until (optional)"
							type="date"
							style={{ maxWidth: 170 }}
							value={until}
							onChange={(event) => setUntil(event.target.value)}
						/>
						<Button onClick={add}>Add</Button>
					</Space.Compact>
				)}
				{editable && view.yourAddress && (
					<Button
						type="link"
						style={{ alignSelf: 'flex-start', padding: 0 }}
						onClick={() => setNetwork(view.yourAddress ?? '')}
					>
						Your address now: {view.yourAddress}
					</Button>
				)}
				{refusal && (
					<Alert
						type="error"
						showIcon
						title={refusal}
					/>
				)}
				{editable && (
					<Flex
						gap={8}
						justify="flex-end"
					>
						<Button
							disabled={!changed || saving}
							onClick={() => {
								setMode(view.mode);
								setExempt(view.exempt);
							}}
						>
							Discard
						</Button>
						<Button
							type="primary"
							disabled={!changed}
							loading={saving}
							onClick={() => void save()}
						>
							Save
						</Button>
					</Flex>
				)}
			</Flex>
		</Card>
	);
}
