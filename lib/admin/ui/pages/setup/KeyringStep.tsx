import { useState } from 'react';
import { Alert, Button, Checkbox, Flex, Input, Space, Typography } from 'antd';
import { CopyOutlined, DownloadOutlined } from '@ant-design/icons';

export interface GeneratedKeyring {
	value: string;
	applied: boolean;
	location?: string;
}

/*
 * The one screen that shows key material (specs/116): at first-run setup and when a super administrator
 * generates a keyring in the console. Nothing shows it again, so continuing waits for the person to say they
 * stored it, and the reminder in the console stays until they have.
 */
export function KeyringStep({
	keyring,
	onContinue,
	continueLabel = 'Continue'
}: {
	keyring: GeneratedKeyring;
	onContinue: () => Promise<void> | void;
	continueLabel?: string;
}) {
	const [saved, setSaved] = useState(false);
	const [copied, setCopied] = useState(false);
	const [busy, setBusy] = useState(false);

	async function copy() {
		await navigator.clipboard.writeText(keyring.value);
		setCopied(true);
	}

	function download() {
		const url = URL.createObjectURL(
			new Blob([`${keyring.value}\n`], { type: 'application/json' })
		);
		const link = document.createElement('a');
		link.href = url;
		link.download = 'foxauth.keyring';
		link.click();
		URL.revokeObjectURL(url);
	}

	async function proceed() {
		setBusy(true);
		try {
			await onContinue();
		} finally {
			setBusy(false);
		}
	}

	return (
		<Flex
			vertical
			gap={16}
		>
			<Typography.Paragraph style={{ margin: 0 }}>
				This is the instance keyring. Stored secrets (application secrets,
				sign-in provider credentials, the mail password, signing keys,
				authenticator secrets) are encrypted with it. It is shown only now.
			</Typography.Paragraph>
			{keyring.applied ? (
				<Alert
					type="info"
					showIcon
					title="In use now"
					description={`Written to ${keyring.location ?? 'the keyring file'}. Keep a copy in a password manager or secrets manager as well, apart from your database backups: a backup cannot be read without it.`}
				/>
			) : (
				<Alert
					type="warning"
					showIcon
					title="Not in use yet"
					description="This deployment has no keyring directory, so the keyring could not be kept on this machine. Set it as the KEYRING secret of your deployment and restart; until then, secrets stay unencrypted."
				/>
			)}
			<Input.TextArea
				readOnly
				value={keyring.value}
				autoSize={{ minRows: 3, maxRows: 6 }}
				style={{ fontFamily: 'monospace' }}
			/>
			<Space>
				<Button
					icon={<CopyOutlined />}
					onClick={() => void copy()}
				>
					{copied ? 'Copied' : 'Copy'}
				</Button>
				<Button
					icon={<DownloadOutlined />}
					onClick={download}
				>
					Download
				</Button>
			</Space>
			<Typography.Link
				href="https://foxauth.dev/docs/deploy/upgrade/#keyring"
				target="_blank"
			>
				Where to keep it, how to rotate it, and what to do if it is lost
			</Typography.Link>
			<Checkbox
				checked={saved}
				onChange={(event) => setSaved(event.target.checked)}
			>
				I have saved this key apart from my database backups
			</Checkbox>
			<Button
				type="primary"
				block
				disabled={!saved}
				loading={busy}
				onClick={() => void proceed()}
			>
				{continueLabel}
			</Button>
		</Flex>
	);
}
