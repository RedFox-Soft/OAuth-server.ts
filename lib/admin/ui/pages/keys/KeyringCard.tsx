import { useEffect, useState } from 'react';
import {
	Alert,
	Button,
	Card,
	Descriptions,
	Flex,
	Modal,
	Tag,
	Typography
} from 'antd';
import { request } from '../../frame/request.js';
import { Link } from '../../frame/router.js';
import { bucketHref, providerHref, userHref } from '../../frame/routes.js';
import { KeyringStep, type GeneratedKeyring } from '../setup/KeyringStep.js';

interface Unreadable {
	kind: string;
	owner: Partial<Record<string, string>>;
	needsKid?: string;
	reason: 'missing-key' | 'integrity' | 'binding';
}

export interface KeyringStatus {
	state: 'none' | 'generated-not-applied' | 'in-use';
	source?: 'environment' | 'file';
	writeKid?: string;
	kids: { kid: string; inKeyring: boolean; values: number }[];
	plaintext: number;
	unreadable: Unreadable[];
	unreadableTotal: number;
	backupConfirmed: { at: string } | null;
	lastPassAt: string | null;
	passPending: boolean;
	regenerated: { note: string } | null;
}

const KIND_LABELS: Record<string, string> = {
	providerSecret: 'Sign-in provider secret',
	providerSigningKey: 'Sign-in provider key',
	clientSecret: 'Application secret',
	smtpPassword: 'Mail password',
	privateKey: 'Signing key',
	totpSecret: 'Authenticator',
	totpPending: 'Authenticator being enrolled',
	dpopNonceSecret: 'DPoP nonce secret',
	errorOriginSalt: 'Error log address key'
};

/* Where the reset path of an unreadable value is (specs/116 FR-017), or null when it has none to open. */
function repairOf(entry: Unreadable): { href: string; label: string } | null {
	const { bucketId, providerId, userId } = entry.owner;
	switch (entry.kind) {
		case 'providerSecret':
		case 'providerSigningKey':
			return bucketId && providerId
				? { href: providerHref(bucketId, providerId), label: 're-enter it' }
				: null;
		case 'smtpPassword':
			return { href: '/admin/settings/integrations', label: 're-enter it' };
		case 'totpSecret':
			return bucketId && userId
				? { href: userHref(bucketId, userId), label: 'reset the authenticator' }
				: null;
		case 'privateKey':
			return bucketId && bucketId !== '#root'
				? { href: bucketHref(bucketId, 'keys'), label: 'generate a new key' }
				: null;
		default:
			return null;
	}
}

function ownerText(entry: Unreadable): string {
	const { clientId, providerId, userId, kid } = entry.owner;
	return clientId ?? providerId ?? userId ?? kid ?? '';
}

/*
 * Encryption at rest (specs/116): whether a keyring is in use, how much is sealed under each key, what is
 * still plaintext, and every secret that cannot be opened with the key it needs and the way to repair it.
 */
export function KeyringCard({ onChanged }: { onChanged?: () => void }) {
	const [status, setStatus] = useState<KeyringStatus | null>(null);
	const [version, setVersion] = useState(0);
	const [generated, setGenerated] = useState<GeneratedKeyring | null>(null);
	const [error, setError] = useState<string | null>(null);

	useEffect(() => {
		let live = true;
		void request<KeyringStatus>('GET', '/admin/api/keyring').then((result) => {
			if (live && result.ok) setStatus(result.data);
		});
		return () => {
			live = false;
		};
	}, [version]);

	async function generate() {
		setError(null);
		const result = await request<GeneratedKeyring & { keyring: string }>(
			'POST',
			'/admin/api/keyring'
		);
		if (!result.ok) {
			setError(result.error.message);
			return;
		}
		setGenerated({
			value: result.data.keyring,
			applied: result.data.applied,
			location: result.data.location
		});
	}

	async function confirmBackup() {
		setError(null);
		const result = await request(
			'POST',
			'/admin/api/keyring/backup-confirmation'
		);
		if (!result.ok) setError(result.error.message);
		setGenerated(null);
		setVersion((current) => current + 1);
		onChanged?.();
	}

	if (!status)
		return (
			<Card
				title="Encryption at rest"
				loading
			/>
		);

	return (
		<Card title="Encryption at rest">
			<Flex
				vertical
				gap={12}
			>
				{error && (
					<Alert
						type="error"
						showIcon
						title={error}
					/>
				)}
				{status.state === 'none' && (
					<Alert
						type="warning"
						showIcon
						title="Stored secrets are not encrypted"
						description="Anyone with a copy of the database can read application secrets, provider credentials, the mail password and signing keys. Generate a keyring to encrypt them."
						action={
							<Button
								type="primary"
								onClick={() => void generate()}
							>
								Generate keyring
							</Button>
						}
					/>
				)}
				{status.state === 'generated-not-applied' && (
					<Alert
						type="warning"
						showIcon
						title="A keyring was generated but is not in use"
						description="Set it as the KEYRING secret of this deployment and restart. Secrets stay unencrypted until then."
					/>
				)}
				{status.state === 'in-use' && !status.backupConfirmed && (
					<Alert
						type="warning"
						showIcon
						title="Confirm the keyring is backed up"
						description="Keep a copy of the keyring apart from the database backups: a backup cannot be read without it."
						action={
							<Button onClick={() => void confirmBackup()}>
								I have saved it
							</Button>
						}
					/>
				)}
				{status.regenerated && (
					<Alert
						type="info"
						showIcon
						title={status.regenerated.note}
					/>
				)}
				<Descriptions
					size="small"
					column={1}
					bordered
				>
					<Descriptions.Item label="Keyring">
						{status.state === 'in-use' ? (
							<Tag color="green">
								in use, from{' '}
								{status.source === 'file' ? 'the keyring file' : 'KEYRING'}
							</Tag>
						) : (
							<Tag color="orange">none</Tag>
						)}
					</Descriptions.Item>
					{status.writeKid && (
						<Descriptions.Item label="New values sealed with">
							<Typography.Text code>{status.writeKid}</Typography.Text>
						</Descriptions.Item>
					)}
					<Descriptions.Item label="Values per key">
						{status.kids.length === 0
							? 'none sealed yet'
							: status.kids.map((k) => (
									<Tag
										key={k.kid}
										color={k.inKeyring ? undefined : 'red'}
									>
										{k.kid}: {k.values}
										{k.inKeyring ? '' : ' (not in the keyring)'}
									</Tag>
								))}
					</Descriptions.Item>
					<Descriptions.Item label="Still unencrypted">
						{status.plaintext}
						{status.passPending ? ' (encryption pass pending)' : ''}
					</Descriptions.Item>
				</Descriptions>
				{status.unreadableTotal > 0 && (
					<>
						<Alert
							type="error"
							showIcon
							title={`${status.unreadableTotal} stored secret(s) cannot be opened with this keyring`}
							description="Each fails closed until it is repaired, or until the key it needs is put back into the keyring."
						/>
						<ul style={{ margin: 0, paddingLeft: 20 }}>
							{status.unreadable.map((entry) => {
								const repair = repairOf(entry);
								return (
									<li key={`${entry.kind} ${JSON.stringify(entry.owner)}`}>
										{KIND_LABELS[entry.kind] ?? entry.kind}{' '}
										<Typography.Text code>{ownerText(entry)}</Typography.Text>
										{entry.needsKid ? ` needs key ${entry.needsKid}` : ''}
										{repair && (
											<>
												{': '}
												<Link href={repair.href}>{repair.label}</Link>
											</>
										)}
									</li>
								);
							})}
						</ul>
					</>
				)}
			</Flex>
			<Modal
				open={generated !== null}
				title="Save the instance keyring"
				footer={null}
				closable={false}
				mask={{ closable: false }}
				width={560}
			>
				{generated && (
					<KeyringStep
						keyring={generated}
						continueLabel="Done"
						onContinue={confirmBackup}
					/>
				)}
			</Modal>
		</Card>
	);
}
