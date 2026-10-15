import { useEffect, useState, type ReactNode } from 'react';
import {
	Alert,
	Button,
	Card,
	Collapse,
	Descriptions,
	Flex,
	Tag,
	Tooltip,
	Typography
} from 'antd';
import { LoadingOutlined } from '@ant-design/icons';
import { request } from '../../frame/request.js';
import { useFeedback } from '../../frame/feedback.js';
import type { RefusalReason, TryResult } from '../../../../federation/types.js';
import { federationApi, type ProviderDetail } from './providerTypes.js';

/*
 * Try sign-in (specs/088 US3): the administrator signs in at the provider in another tab, through this bucket's
 * real callback, and this tab shows what the provider answered and what a real sign-in would do — with nothing
 * written. The result comes back by polling, never by a redirect into the console: the console's cookie is
 * SameSite=Strict, so a navigation that began at the provider would arrive signed out.
 */

const POLL_MS = 2000;
const HINT_AFTER_MS = 60_000;

interface Started {
	tryRef: string;
	expiresAt: string;
	startedAt: number;
	/* Shown when the browser refused to open the tab, so the administrator can open it themselves. */
	manualUrl: string | null;
}

const REFUSALS: Record<RefusalReason, string> = {
	no_email: 'the provider sent no email address, so there is nobody to match',
	domain_not_allowed:
		"the address's domain isn't one this provider may sign in",
	link_not_permitted:
		"an account has this address, but this provider may not claim it — the address isn't verified, or the provider isn't trusted for addresses",
	provisioning_closed:
		"no account has this address, and this provider doesn't create accounts",
	inactive: 'the account is locked or deactivated',
	not_provisioned: 'the directory has provisioned nobody matching this sign-in',
	link_conflict:
		'the matching person is already linked to another identity at this provider'
};

function accountName(account: { id: string; email?: string } | undefined) {
	return account?.email ?? account?.id ?? 'the account';
}

function outcomeLine(outcome: NonNullable<TryResult['outcome']>): ReactNode {
	const who = accountName(outcome.account);
	switch (outcome.kind) {
		case 'signin':
			return `Sign in ${who}, already linked to this identity.`;
		case 'link':
			return `Link this identity to ${who} and sign in.`;
		case 'password_required':
			return `Ask for ${who}'s password first, then link this identity to it.`;
		case 'provision':
			return `Create a new account (${outcome.verified ? 'address verified' : 'address not verified'}).`;
		case 'correlate':
			return `Sign in ${who}, the person ${outcome.connection ? `provisioned by ${outcome.connection.displayName}` : 'the directory provisioned'}.`;
		case 'conflict':
			return `Refuse: ${REFUSALS.link_conflict}${outcome.account ? ` (${who})` : ''}.`;
		case 'refuse':
			return `Refuse: ${outcome.reason ? REFUSALS[outcome.reason] : 'not permitted'}${outcome.account ? ` (${who})` : ''}.`;
	}
}

function errorLine(error: NonNullable<TryResult['error']>): string {
	if (error.stage === 'declined') {
		return `The provider declined: ${error.reason}${error.description ? ` — ${error.description}` : ''}.`;
	}
	if (error.reason === 'issuer_mismatch') {
		return 'The response named another issuer than this provider, so a real sign-in would be refused.';
	}
	if (error.reason === 'issuer_missing') {
		return 'The provider says it names itself in every response, but this one did not, so a real sign-in would be refused.';
	}
	if (error.reason === 'federation_off') {
		return 'Federation was switched off on this instance during the try.';
	}
	if (error.reason === 'provider_removed') {
		return 'The provider was deleted during the try.';
	}
	if (error.reason === 'no_code') {
		return 'The provider sent the browser back without a code.';
	}
	return error.stage === 'upstream'
		? `The exchange with the provider failed: ${error.reason}.`
		: `The provider's answer was refused: ${error.reason}.`;
}

/* The claims worth reading about the try, without the round trip's own bookkeeping. */
function claimRows(claims: Record<string, unknown>) {
	return Object.entries(claims).map(([name, value]) => ({
		key: name,
		label: name,
		children: (
			<Typography.Text code>
				{typeof value === 'string' ? value : JSON.stringify(value)}
			</Typography.Text>
		)
	}));
}

export function useTrySignIn(
	bucketId: string,
	provider: ProviderDetail | null,
	canEdit: boolean
): { button: ReactNode; panel: ReactNode } {
	const feedback = useFeedback();
	const [started, setStarted] = useState<Started | null>(null);
	const [result, setResult] = useState<TryResult | null>(null);
	const [expired, setExpired] = useState(false);
	const [now, setNow] = useState(() => Date.now());
	const [busy, setBusy] = useState(false);

	const base = provider ? `${federationApi(bucketId, provider.id)}/try` : '';

	useEffect(() => {
		if (!started || result || expired) return;
		const timer = setInterval(() => {
			setNow(Date.now());
			if (Date.now() >= new Date(started.expiresAt).getTime()) {
				setExpired(true);
				return;
			}
			void request<{ status: 'waiting' | 'done'; result?: TryResult }>(
				'GET',
				`${base}/${encodeURIComponent(started.tryRef)}`
			).then((r) => {
				if (!r.ok) {
					if (r.status === 404) setExpired(true);
					return;
				}
				if (r.data.status === 'done' && r.data.result) setResult(r.data.result);
			});
		}, POLL_MS);
		return () => clearInterval(timer);
	}, [started, result, expired, base]);

	async function start() {
		if (!provider) return;
		/*
		 * Opened before the request, inside the click, because a browser blocks a tab opened after an await; it is
		 * pointed at the provider once the server answers, and detached from this page first.
		 */
		const tab = window.open('about:blank', '_blank');
		setBusy(true);
		try {
			const r = await request<{
				tryRef: string;
				authorizationUrl: string;
				expiresAt: string;
			}>('POST', base);
			if (!r.ok) {
				tab?.close();
				feedback.failed(r);
				return;
			}
			if (tab) {
				tab.opener = null;
				tab.location.href = r.data.authorizationUrl;
			}
			setResult(null);
			setExpired(false);
			setStarted({
				tryRef: r.data.tryRef,
				expiresAt: r.data.expiresAt,
				startedAt: Date.now(),
				manualUrl: tab ? null : r.data.authorizationUrl
			});
		} finally {
			setBusy(false);
		}
	}

	function dismiss() {
		setStarted(null);
		setResult(null);
		setExpired(false);
	}

	const off = provider !== null && !provider.capabilities.trySignIn;
	const button =
		provider && canEdit ? (
			<Tooltip
				title={
					off
						? 'Federation is switched off on this instance (Settings), so there is no callback to try.'
						: 'Sign in at the provider in a new tab and see what a real sign-in would do. Nothing is written.'
				}
			>
				<Button
					disabled={off || busy || (started !== null && !result && !expired)}
					loading={busy}
					onClick={() => void start()}
				>
					Try sign-in
				</Button>
			</Tooltip>
		) : null;

	let panel: ReactNode = null;
	if (provider && started && !result) {
		panel = (
			<Card
				title="Try sign-in"
				extra={
					<Button onClick={dismiss}>{expired ? 'Close' : 'Cancel'}</Button>
				}
				style={{ marginBottom: 16 }}
			>
				<Flex
					vertical
					gap={12}
				>
					{started.manualUrl && (
						<Alert
							type="info"
							showIcon
							title="The browser didn't open a new tab"
							action={
								<Button
									href={started.manualUrl}
									target="_blank"
									rel="noopener noreferrer"
								>
									Open {provider.displayName}
								</Button>
							}
						/>
					)}
					{expired ? (
						<Typography.Text type="secondary">
							The try ended without an answer. Start it again when you are
							ready.
						</Typography.Text>
					) : (
						<Typography.Text>
							<LoadingOutlined /> Waiting for the sign-in at{' '}
							{provider.displayName} in the other tab…
						</Typography.Text>
					)}
					{(expired || now - started.startedAt >= HINT_AFTER_MS) && (
						<Alert
							type="warning"
							showIcon
							title="Nothing back yet?"
							description={
								<>
									If {provider.displayName} showed an error about the redirect
									address, this project's callback is not registered there. Add
									it to the application at {provider.displayName}:{' '}
									<Typography.Text
										code
										copyable={{ text: provider.callbackUri }}
									>
										{provider.callbackUri}
									</Typography.Text>
								</>
							}
						/>
					)}
				</Flex>
			</Card>
		);
	} else if (provider && result) {
		panel = (
			<Card
				title="Try result"
				extra={<Button onClick={dismiss}>Dismiss</Button>}
				style={{ marginBottom: 16 }}
			>
				<Flex
					vertical
					gap={16}
				>
					{!result.providerEnabled && (
						<Alert
							type="info"
							showIcon
							title="This provider is off. A real sign-in through it is refused until it is enabled; once on, it would do what is shown here."
						/>
					)}
					{result.error && (
						<Alert
							type="error"
							showIcon
							title={errorLine(result.error)}
						/>
					)}
					{result.answer && (
						<div>
							<Typography.Title level={5}>
								What {provider.displayName} answered
							</Typography.Title>
							<Descriptions
								column={1}
								size="small"
								items={[
									{
										label: 'Subject',
										children: (
											<Typography.Text code>
												{result.answer.subject}
											</Typography.Text>
										)
									},
									{
										label: 'Email',
										children: result.answer.email ? (
											<>
												{result.answer.email}{' '}
												<Tag
													color={
														result.answer.emailVerified ? 'green' : 'default'
													}
												>
													{result.answer.emailVerified
														? 'Verified'
														: 'Not verified'}
												</Tag>
											</>
										) : (
											<Typography.Text type="secondary">none</Typography.Text>
										)
									}
								]}
							/>
							<Collapse
								size="small"
								style={{ marginTop: 8 }}
								items={[
									{
										key: 'claims',
										label: `All claims (${Object.keys(result.answer.claims).length})`,
										children: (
											<Descriptions
												column={1}
												size="small"
												bordered
												items={claimRows(result.answer.claims)}
											/>
										)
									}
								]}
							/>
						</div>
					)}
					{result.outcome && (
						<div>
							<Typography.Title level={5}>
								What a real sign-in would do now
							</Typography.Title>
							<Typography.Text
								type={
									result.outcome.kind === 'refuse' ||
									result.outcome.kind === 'conflict'
										? 'danger'
										: undefined
								}
							>
								{outcomeLine(result.outcome)}
							</Typography.Text>
						</div>
					)}
					{result.callbackProvisional && (
						<Alert
							type="warning"
							showIcon
							title="This project has no address yet, so its callback changes when it gets one. Register the new callback at the provider then."
						/>
					)}
					<Typography.Text type="secondary">
						Nothing was saved: no account, link or session. To try another
						account, open the console in a private window.
					</Typography.Text>
				</Flex>
			</Card>
		);
	}
	return { button, panel };
}
