import { useCallback, useEffect, useState } from 'react';
import {
	Alert,
	Button,
	Drawer,
	Flex,
	Input,
	Space,
	Tabs,
	Tag,
	Typography
} from 'antd';
import {
	browserSupportsWebAuthn,
	startRegistration,
	WebAuthnError,
	type PublicKeyCredentialCreationOptionsJSON
} from '@simplewebauthn/browser';
import type { PasskeyView } from '../../../passkeys/ways_in.js';
import { request } from '../frame/request.js';
import { useFeedback } from '../frame/feedback.js';
import { useConfirm } from '../frame/confirm.js';
import { EmptyState, LoadFailed } from '../frame/states.js';
import { OwnSignInsList } from './OwnSignInsDrawer.js';

interface PasskeySignals {
	rpId: string;
	userId: string;
	acceptedCredentialIds: string[];
	email: string;
	label: string;
}

interface MePasskeysView {
	accepted: boolean;
	passkeys: PasskeyView[];
	availability:
		| 'ready'
		| 'not_accepted'
		| 'provider_only'
		| 'no_mail'
		| 'unconfirmed'
		| 'full';
	freshness: 'strong' | 'password' | 'any' | 'stale';
	verified: boolean;
	mailReady: boolean;
	consolePasskeyRequired: boolean;
	liveAdd: boolean;
	liveRemoveId: string | null;
	signals: PasskeySignals | null;
}

interface SignalApi {
	signalAllAcceptedCredentials?: (options: {
		rpId: string;
		userId: string;
		allAcceptedCredentialIds: string[];
	}) => Promise<void>;
	signalCurrentUserDetails?: (options: {
		rpId: string;
		userId: string;
		name: string;
		displayName: string;
	}) => Promise<void>;
}

function sendSignals(signals: PasskeySignals | null): void {
	if (!signals || typeof window === 'undefined') return;
	const api = (window as unknown as { PublicKeyCredential?: SignalApi })
		.PublicKeyCredential;
	if (!api) return;
	if (typeof api.signalAllAcceptedCredentials === 'function') {
		void api
			.signalAllAcceptedCredentials({
				rpId: signals.rpId,
				userId: signals.userId,
				allAcceptedCredentialIds: signals.acceptedCredentialIds
			})
			.catch(() => {});
	}
	if (typeof api.signalCurrentUserDetails === 'function') {
		void api
			.signalCurrentUserDetails({
				rpId: signals.rpId,
				userId: signals.userId,
				name: signals.label,
				displayName: signals.email
			})
			.catch(() => {});
	}
}

function deviceLabel(createdOn: PasskeyView['createdOn']): string {
	return `${createdOn.browser} on ${createdOn.system}`;
}

function formatDate(iso: string): string {
	return new Date(iso).toLocaleString(undefined, {
		dateStyle: 'medium',
		timeStyle: 'short'
	});
}

function stateTag(state: PasskeyView['state']) {
	switch (state) {
		case 'works':
			return <Tag color="green">Active</Tag>;
		case 'off':
			return <Tag>Off</Tag>;
		case 'old_address':
			return <Tag color="orange">Old address</Tag>;
		case 'copied':
			return <Tag color="red">Not usable</Tag>;
	}
}

export type OwnAccountTab = 'passkeys' | 'signIns';

/*
 * The signed-in administrator's personal drawer (specs/144 contracts/console-ui.md §1): Passkeys and Recent
 * sign-ins side by side from their email in the header, since administrators have no `/account/security` page.
 */
export function OwnAccountDrawer({
	open,
	initialTab = 'signIns',
	banner,
	onClose
}: {
	open: boolean;
	initialTab?: OwnAccountTab;
	banner?: { type: 'success' | 'warning'; text: string } | null;
	onClose: () => void;
}) {
	return (
		<Drawer
			title="Your account"
			open={open}
			onClose={onClose}
			size="large"
			destroyOnHidden
		>
			{open && (
				<Tabs
					key={initialTab}
					defaultActiveKey={initialTab}
					items={[
						{
							key: 'passkeys',
							label: 'Passkeys',
							children: <OwnPasskeysTab banner={banner ?? null} />
						},
						{
							key: 'signIns',
							label: 'Recent sign-ins',
							children: (
								<>
									<OwnSignInsList />
									<Typography.Paragraph
										type="secondary"
										style={{ marginTop: 16 }}
									>
										Something you don&apos;t recognise? Ask a super
										administrator to look at your sign-ins and sign you out
										everywhere.
									</Typography.Paragraph>
								</>
							)
						}
					]}
				/>
			)}
		</Drawer>
	);
}

function OwnPasskeysTab({
	banner
}: {
	banner: { type: 'success' | 'warning'; text: string } | null;
}) {
	const feedback = useFeedback();
	const confirm = useConfirm();
	const [view, setView] = useState<MePasskeysView | null>(null);
	const [error, setError] = useState<string | null>(null);
	const [loading, setLoading] = useState(true);
	const [busy, setBusy] = useState(false);
	const [notice, setNotice] = useState<{
		type: 'success' | 'info' | 'warning' | 'error';
		text: string;
	} | null>(banner);
	const [renamingId, setRenamingId] = useState<string | null>(null);
	const [renameValue, setRenameValue] = useState('');

	const load = useCallback(async () => {
		try {
			const result = await request<MePasskeysView>(
				'GET',
				'/admin/api/me/passkeys'
			);
			if (!result.ok) {
				setError(result.error.message);
				return;
			}
			setError(null);
			setView(result.data);
			sendSignals(result.data.signals);
		} finally {
			setLoading(false);
		}
	}, []);

	useEffect(() => {
		void load();
	}, [load]);

	async function onVerifyEmail() {
		setBusy(true);
		try {
			const res = await request<{
				alreadyVerified?: boolean;
				codeUrl?: string;
			}>('POST', '/admin/api/me/verification');
			if (!res.ok) {
				feedback.refused(res);
				return;
			}
			if (res.data.alreadyVerified) {
				await load();
				return;
			}
			if (res.data.codeUrl) {
				window.open(res.data.codeUrl, '_blank', 'noopener');
				setNotice({
					type: 'info',
					text: 'Verification code sent. Complete verification on the page that opened, then reload.'
				});
			} else {
				setNotice({
					type: 'info',
					text: 'Verification email sent. Follow the link in your inbox, then reload.'
				});
			}
		} finally {
			setBusy(false);
		}
	}

	async function onSendAddLink() {
		setBusy(true);
		setNotice(null);
		try {
			const res = await request<{ sent: boolean }>(
				'POST',
				'/admin/api/me/passkeys/add-link'
			);
			if (!res.ok) {
				setNotice({ type: 'error', text: res.error.message });
				return;
			}
			setNotice({
				type: 'info',
				text: 'Check your email and open the confirmation link in this browser to add a passkey.'
			});
		} finally {
			setBusy(false);
		}
	}

	async function onAddPasskey() {
		if (!browserSupportsWebAuthn()) {
			setNotice({
				type: 'warning',
				text: 'This browser does not support passkeys.'
			});
			return;
		}
		setBusy(true);
		setNotice(null);
		try {
			const opts = await request<{
				options: PublicKeyCredentialCreationOptionsJSON;
			}>('POST', '/admin/api/me/passkeys/add/options');
			if (!opts.ok) {
				setNotice({ type: 'error', text: opts.error.message });
				return;
			}
			let credential;
			try {
				credential = await startRegistration({
					optionsJSON: opts.data.options
				});
			} catch (err) {
				if (
					err instanceof WebAuthnError &&
					err.code === 'ERROR_CEREMONY_ABORTED'
				) {
					setNotice({
						type: 'info',
						text: 'Passkey creation was cancelled.'
					});
					return;
				}
				setNotice({
					type: 'error',
					text: 'Your device did not create a passkey. Try again.'
				});
				return;
			}
			const saved = await request<{ passkey: PasskeyView }>(
				'POST',
				'/admin/api/me/passkeys/add',
				{ credential: JSON.stringify(credential) }
			);
			if (!saved.ok) {
				setNotice({ type: 'error', text: saved.error.message });
				return;
			}
			feedback.done('Passkey added.');
			await load();
		} finally {
			setBusy(false);
		}
	}

	async function onRename(passkeyId: string) {
		setBusy(true);
		setNotice(null);
		try {
			const res = await request<{ passkey: PasskeyView }>(
				'PATCH',
				`/admin/api/me/passkeys/${encodeURIComponent(passkeyId)}`,
				{ name: renameValue }
			);
			if (!res.ok) {
				setNotice({ type: 'error', text: res.error.message });
				return;
			}
			setRenamingId(null);
			feedback.done('Passkey renamed.');
			await load();
		} finally {
			setBusy(false);
		}
	}

	async function onSendRemoveLink(passkeyId: string) {
		setBusy(true);
		setNotice(null);
		try {
			const res = await request<{ sent: boolean }>(
				'POST',
				`/admin/api/me/passkeys/${encodeURIComponent(passkeyId)}/remove-link`
			);
			if (!res.ok) {
				setNotice({ type: 'error', text: res.error.message });
				return;
			}
			setNotice({
				type: 'info',
				text: 'Check your email and open the confirmation link in this browser to remove this passkey.'
			});
		} finally {
			setBusy(false);
		}
	}

	async function onRemove(passkey: PasskeyView) {
		const yes = await confirm('me.passkey.remove', {
			target: passkey.name ?? deviceLabel(passkey.createdOn),
			consequences: [
				'This passkey stops working immediately.',
				'A notification email is sent to your address.'
			]
		});
		if (!yes) return;
		setBusy(true);
		setNotice(null);
		try {
			const res = await request<{ removed: boolean }>(
				'DELETE',
				`/admin/api/me/passkeys/${encodeURIComponent(passkey.id)}`
			);
			if (!res.ok) {
				setNotice({ type: 'error', text: res.error.message });
				return;
			}
			feedback.done('Passkey removed.');
			await load();
		} finally {
			setBusy(false);
		}
	}

	if (error !== null) {
		return (
			<LoadFailed
				reason={error}
				onRetry={() => {
					setLoading(true);
					void load();
				}}
			/>
		);
	}
	if (loading || view === null) return null;

	const reauthHref = `/admin/login?reauth=1&next=${encodeURIComponent('/admin?account=passkeys')}`;

	return (
		<Flex
			vertical
			gap={16}
		>
			{notice && (
				<Alert
					type={notice.type}
					showIcon
					title={notice.text}
				/>
			)}
			{!view.accepted && (
				<Alert
					type="info"
					showIcon
					title="Passkeys are currently turned off for administrators."
					description="A super administrator can turn Passkeys on under Administrators → Sign-in."
				/>
			)}
			{view.accepted && view.availability === 'unconfirmed' && (
				<Alert
					type="warning"
					showIcon
					title="Verify your email address before adding a passkey."
					action={
						<Button
							size="small"
							loading={busy}
							onClick={() => void onVerifyEmail()}
						>
							Send me a verification email
						</Button>
					}
				/>
			)}
			{view.accepted && view.availability === 'no_mail' && (
				<Alert
					type="warning"
					showIcon
					title="Mail delivery must be configured before administrators can add passkeys."
				/>
			)}
			{view.accepted && view.availability === 'provider_only' && (
				<Alert
					type="info"
					showIcon
					title="Accounts that sign in only through an identity provider cannot add a passkey."
				/>
			)}
			{view.accepted && view.availability === 'full' && (
				<Alert
					type="info"
					showIcon
					title="You have reached the maximum of 20 passkeys."
				/>
			)}
			{view.accepted && view.availability === 'ready' && (
				<Flex
					gap={8}
					wrap
					align="center"
				>
					{view.freshness === 'strong' || view.liveAdd ? (
						<Button
							type="primary"
							loading={busy}
							onClick={() => void onAddPasskey()}
						>
							Add a passkey
						</Button>
					) : view.freshness === 'password' ? (
						<Button
							type="primary"
							loading={busy}
							onClick={() => void onSendAddLink()}
						>
							Email me a link to add a passkey
						</Button>
					) : (
						<Button
							type="primary"
							href={reauthHref}
						>
							Sign in again to add a passkey
						</Button>
					)}
					{view.liveAdd && (
						<Typography.Text type="secondary">
							Email link confirmed — click Add a passkey to finish.
						</Typography.Text>
					)}
				</Flex>
			)}

			{view.passkeys.length === 0 ? (
				<EmptyState purpose="You have no passkeys yet." />
			) : (
				<Flex
					vertical
					gap={12}
				>
					{view.passkeys.map((passkey) => {
						const canRemoveDirectly =
							view.freshness === 'strong' || view.liveRemoveId === passkey.id;
						return (
							<Flex
								key={passkey.id}
								vertical
								gap={6}
								style={{
									padding: '12px 0',
									borderBottom: '1px solid rgba(5, 5, 5, 0.08)'
								}}
							>
								<Flex
									justify="space-between"
									align="center"
									gap={8}
									wrap
								>
									<Space
										size={6}
										wrap
									>
										<Typography.Text strong>
											{passkey.name ?? deviceLabel(passkey.createdOn)}
										</Typography.Text>
										{stateTag(passkey.state)}
									</Space>
									<Space size={8}>
										{view.freshness !== 'stale' && (
											<Button
												size="small"
												onClick={() => {
													setRenamingId(passkey.id);
													setRenameValue(passkey.name ?? '');
												}}
											>
												Rename
											</Button>
										)}
										{canRemoveDirectly ? (
											<Button
												size="small"
												danger
												loading={busy}
												onClick={() => void onRemove(passkey)}
											>
												Remove
											</Button>
										) : view.freshness === 'password' ? (
											<Button
												size="small"
												danger
												loading={busy}
												onClick={() => void onSendRemoveLink(passkey.id)}
											>
												Email link to remove
											</Button>
										) : (
											<Button
												size="small"
												href={reauthHref}
											>
												Sign in again to remove
											</Button>
										)}
									</Space>
								</Flex>
								<Typography.Text type="secondary">
									Added {formatDate(passkey.createdAt)} ·{' '}
									{passkey.lastUsedAt
										? `Last used ${formatDate(passkey.lastUsedAt)}`
										: 'Never used'}
								</Typography.Text>
								{renamingId === passkey.id && (
									<Flex
										gap={8}
										align="center"
									>
										<Input
											size="small"
											value={renameValue}
											maxLength={64}
											placeholder="Passkey name"
											onChange={(e) => setRenameValue(e.target.value)}
										/>
										<Button
											size="small"
											type="primary"
											loading={busy}
											onClick={() => void onRename(passkey.id)}
										>
											Save
										</Button>
										<Button
											size="small"
											onClick={() => setRenamingId(null)}
										>
											Cancel
										</Button>
									</Flex>
								)}
							</Flex>
						);
					})}
				</Flex>
			)}
		</Flex>
	);
}
