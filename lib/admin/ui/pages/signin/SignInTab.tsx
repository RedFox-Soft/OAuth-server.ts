import { useCallback, useEffect, useState, type ReactNode } from 'react';
import {
	Alert,
	Button,
	Card,
	Col,
	Descriptions,
	Flex,
	Row,
	Segmented,
	Switch,
	Typography
} from 'antd';
import type { FederationProvider } from '../../../../federation/types.js';
import { DEFAULT_BUCKET_ID } from '../../../consts.js';
import { Link, useLeaveGuard } from '../../frame/router.js';
import { bucketHref } from '../../frame/routes.js';
import { request } from '../../frame/request.js';
import { useFeedback } from '../../frame/feedback.js';
import { useConfirm } from '../../frame/confirm.js';
import type { BucketCan } from '../../frame/can.js';
import { SaveBar } from '../../settings/SaveBar.js';
import type { Change } from '../../settings/model.js';
import type { BucketSummary, BucketView } from '../bucketView.js';
import { SignInPreview } from './SignInPreview.js';

/* The five settings that decide how people get into a bucket. */
interface Policy {
	passwordLogin: boolean;
	totpRequired: boolean;
	registrationOpen: boolean;
	emailVerificationRequired: boolean;
	verificationMethod: 'link' | 'code';
}

const LABELS: Record<keyof Policy, string> = {
	passwordLogin: 'Password sign-in',
	totpRequired: 'Require an authenticator app',
	registrationOpen: 'Self-service sign-up',
	emailVerificationRequired: 'Require a verified email address',
	verificationMethod: 'Verification method'
};

export function policyOf(bucket: BucketView): Policy {
	return {
		passwordLogin: bucket.passwordLogin,
		totpRequired: bucket.totpRequired,
		registrationOpen: bucket.registrationOpen,
		emailVerificationRequired: bucket.emailVerificationRequired,
		verificationMethod: bucket.verificationMethod
	};
}

/* A key for the tab, so a saved bucket remounts it with the stored values as the new starting point. */
export function signInKey(bucket: BucketView): string {
	return JSON.stringify(policyOf(bucket));
}

/* What turning password sign-in to the console off would do (GET /admin/api/admins/sign-in-readiness). */
interface SignInReadiness {
	signedInWith: string | null;
	callerLinkedAt: string[];
	reachableSuperAdministrators: number;
	unlinkedAdministrators: { id: string; email: string }[];
}

/* The server's account of a change that can shut people out (specs/083 data-model §3). */
interface Preview {
	confirmationRequired: true;
	consequences: string[];
	expect: Record<string, number>;
}

function isPreview(body: unknown): body is Preview {
	return (
		typeof body === 'object' &&
		body !== null &&
		(body as { confirmationRequired?: unknown }).confirmationRequired ===
			true &&
		Array.isArray((body as { consequences?: unknown }).consequences)
	);
}

function plural(n: number, one: string, many: string): string {
	return `${n.toLocaleString()} ${n === 1 ? one : many}`;
}

/* One setting: its name and control on a line, what people experience under it, then anything it needs said. */
function Setting({
	title,
	control,
	effect,
	children
}: {
	title: string;
	control: ReactNode;
	effect: ReactNode;
	children?: ReactNode;
}) {
	return (
		<Flex
			vertical
			gap={6}
		>
			<Flex
				justify="space-between"
				align="center"
				gap={12}
				wrap
			>
				<Typography.Text strong>{title}</Typography.Text>
				{control}
			</Flex>
			<Typography.Text type="secondary">{effect}</Typography.Text>
			{children}
		</Flex>
	);
}

/*
 * How people get into a bucket (specs/083), on a tab of its own rather than in a dialog that answered after the
 * fact. Every switch says what the people in the bucket will experience; what the server would refuse is shown
 * unavailable, with the reason and the way out, before anyone tries; and a change that tightens who can get
 * in is sent once to learn its cost — the server answers with counts — and saved only when those counts are
 * confirmed. The same tab serves the console's own bucket, whose guards protect the only surface that could
 * undo a mistake there.
 */
export function SignInTab({
	bucket,
	summary,
	summaryFailed,
	can,
	consoleBucket = false,
	onSaved
}: {
	bucket: BucketView;
	summary: BucketSummary | null;
	summaryFailed: boolean;
	can: BucketCan;
	consoleBucket?: boolean;
	onSaved: () => void;
}) {
	const base = `/admin/api/projects/${encodeURIComponent(bucket._id)}`;
	const feedback = useFeedback();
	const confirm = useConfirm();
	const baseline = policyOf(bucket);
	const [draft, setDraft] = useState<Policy>(baseline);
	const [saving, setSaving] = useState(false);
	/*
	 * Both stay on the tab until something changes: a refusal explains a rule about the whole bucket, and an
	 * advisory says what a saved setting does not yet do. A toast is gone before either has been read.
	 */
	const [refusal, setRefusal] = useState<string | null>(null);
	const [advisory, setAdvisory] = useState<string | null>(null);
	const [providers, setProviders] = useState<FederationProvider[] | null>(null);
	const [readiness, setReadiness] = useState<SignInReadiness | null>(null);
	const [selfVerified, setSelfVerified] = useState(true);
	const [sending, setSending] = useState(false);
	const [contextLoading, setContextLoading] = useState(true);

	// Every state write follows an await, so the mount effect calls this without setting `contextLoading` first.
	const fetchContext = useCallback(async () => {
		try {
			const [p, r, me] = await Promise.all([
				request<FederationProvider[]>('GET', `${base}/federation`),
				consoleBucket
					? request<SignInReadiness>(
							'GET',
							'/admin/api/admins/sign-in-readiness'
						)
					: Promise.resolve(null),
				consoleBucket
					? request<{ verified?: boolean }>('GET', '/admin/api/me')
					: Promise.resolve(null)
			]);
			if (p.ok) setProviders(p.data);
			if (r?.ok) setReadiness(r.data);
			if (me?.ok) setSelfVerified(me.data.verified === true);
		} finally {
			setContextLoading(false);
		}
	}, [base, consoleBucket]);
	useEffect(() => {
		void fetchContext();
	}, [fetchContext]);

	const keys = Object.keys(LABELS) as (keyof Policy)[];
	const dirty = keys.filter((key) => draft[key] !== baseline[key]);
	useLeaveGuard(dirty.length > 0, dirty.length);
	const changes: Change[] = dirty.map((key) => ({
		key,
		label: LABELS[key],
		group: 'sign-in',
		from: baseline[key],
		to: draft[key]
	}));

	function set<K extends keyof Policy>(key: K, value: Policy[K]) {
		setRefusal(null);
		setDraft((d) => ({ ...d, [key]: value }));
	}

	/*
	 * Sent without consent first. A change that can shut people out is answered with the server's own
	 * account of it, asked as a danger question, and sent again carrying the counts that were shown — so
	 * consent is always to the numbers the operator read, and a count that moved in between is asked again.
	 */
	async function save(consent?: Record<string, number>): Promise<void> {
		const body: Record<string, unknown> = Object.fromEntries(
			dirty.map((key) => [key, draft[key]])
		);
		if (consent) {
			body.confirm = true;
			body.expect = consent;
		}
		setSaving(true);
		let preview: Preview | null = null;
		try {
			setAdvisory(null);
			const result = await request<{ advisory?: string }>('PATCH', base, body);
			if (result.ok) {
				feedback.done(`Sign-in of ${bucket.name} saved.`);
				if (result.data.advisory) setAdvisory(result.data.advisory);
				onSaved();
				return;
			}
			if (result.status === 409 && isPreview(result.error)) {
				preview = result.error;
			} else if (result.status >= 500 || result.error.error_reference) {
				feedback.failed(result);
			} else {
				setRefusal(result.error.message);
			}
		} finally {
			setSaving(false);
		}
		if (!preview) return;
		const agreed = await confirm('bucket.signIn.confirm', {
			target: bucket.name,
			consequences: consent
				? [
						'What this change affects has changed since you last looked.',
						...preview.consequences
					]
				: preview.consequences
		});
		if (agreed) await save(preview.expect);
	}

	async function onVerifySelf() {
		setSending(true);
		try {
			const result = await request<{
				alreadyVerified?: boolean;
				codeUrl?: string;
			}>('POST', '/admin/api/me/verification');
			if (!result.ok) {
				feedback.refused(result);
				return;
			}
			if (result.data.alreadyVerified) {
				setSelfVerified(true);
				return;
			}
			if (result.data.codeUrl) {
				window.open(result.data.codeUrl, '_blank', 'noopener');
				feedback.done(
					'Verification code sent. Enter the code from your email on the page that opened.'
				);
			} else {
				feedback.done(
					'Verification link sent. Follow it from your inbox, then reload this page.'
				);
			}
		} finally {
			setSending(false);
		}
	}

	const editable = can.editSettings;
	const enabled = (providers ?? []).filter((p) => p.enabled);
	const creating = enabled.filter((p) => p.provisioning === 'jit');
	const providersHref = consoleBucket
		? '/admin/administrators/identity-providers'
		: bucketHref(bucket._id, 'identity-providers');
	const counts = summary;
	const defaultBucket = bucket._id === DEFAULT_BUCKET_ID;
	const applicationsLine =
		defaultBucket && counts?.applications !== undefined
			? `This changes sign-in for ${plural(counts.applications, 'application', 'applications')}.`
			: null;
	const mayTurnPasswordsOff =
		readiness !== null &&
		readiness.signedInWith !== null &&
		readiness.callerLinkedAt.includes(readiness.signedInWith);
	const mailReady = summary?.mailDeliveryConfigured !== false;
	const people = consoleBucket ? 'administrators' : 'people';

	/* Why a switch cannot move in the direction it would now move, or null. */
	const passwordBlock = !draft.passwordLogin
		? null
		: consoleBucket
			? mayTurnPasswordsOff
				? null
				: "To turn it off, sign in through one of this project's identity providers first. That proves another way in works before this one closes."
			: providers !== null && enabled.length === 0
				? 'Enable an identity provider first, otherwise nobody could sign in.'
				: null;
	const verificationBlock = draft.emailVerificationRequired
		? null
		: !mailReady
			? "This server can't send email yet. An instance administrator must configure mail delivery."
			: consoleBucket && !selfVerified
				? 'Verify your own address first, so the requirement can never lock you out.'
				: null;

	function note(text: string, type: 'info' | 'warning' = 'info') {
		return (
			<Alert
				type={type}
				showIcon
				title={text}
				description={applicationsLine ?? undefined}
			/>
		);
	}

	const countsUnavailable = summaryFailed ? (
		<Typography.Text type="secondary">
			Counts are unavailable right now; the server states them when you save.
		</Typography.Text>
	) : null;

	/*
	 * The page people meet, beside the switches that decide it (specs/091): the draft for an editor, the stored
	 * settings for anyone who can only read them. Below the switches on a narrow window.
	 */
	const preview = (
		<SignInPreview
			bucketId={bucket._id}
			draft={editable ? draft : baseline}
			providers={providers}
			federationOn={summary ? summary.federationEnabled : null}
			loading={contextLoading || (summary === null && !summaryFailed)}
		/>
	);
	const besidePreview = (content: ReactNode) => (
		<Row gutter={[16, 16]}>
			<Col
				xs={24}
				xl={14}
			>
				{content}
			</Col>
			<Col
				xs={24}
				xl={10}
			>
				{preview}
			</Col>
		</Row>
	);

	if (!editable) {
		const yes = (v: boolean) => (v ? 'On' : 'Off');
		return besidePreview(
			<Flex
				vertical
				gap={16}
			>
				<Alert
					type="info"
					showIcon
					title={
						consoleBucket
							? 'Only super administrators can change how administrators sign in.'
							: 'Only members of the team that owns this project can change how people sign in.'
					}
				/>
				<Card>
					<Descriptions
						column={1}
						items={[
							{
								key: 'password',
								label: LABELS.passwordLogin,
								children: yes(baseline.passwordLogin)
							},
							{
								key: 'providers',
								label: 'Identity providers',
								children: `${String(enabled.length)} enabled`
							},
							{
								key: 'totp',
								label: LABELS.totpRequired,
								children: yes(baseline.totpRequired)
							},
							{
								key: 'signup',
								label: LABELS.registrationOpen,
								children: baseline.registrationOpen ? 'Open' : 'Closed'
							},
							{
								key: 'verification',
								label: LABELS.emailVerificationRequired,
								children: baseline.emailVerificationRequired
									? `Required · ${baseline.verificationMethod === 'code' ? '6-digit code' : 'link'}`
									: 'Not required'
							}
						]}
					/>
				</Card>
			</Flex>
		);
	}

	return besidePreview(
		<Flex
			vertical
			gap={16}
		>
			{refusal !== null && (
				<Alert
					type="error"
					showIcon
					title={refusal}
					closable={{ onClose: () => setRefusal(null) }}
				/>
			)}
			{advisory !== null && (
				<Alert
					type="warning"
					showIcon
					title="Saved, with a warning"
					description={advisory}
				/>
			)}

			<Card title="Ways to sign in">
				<Flex
					vertical
					gap={20}
				>
					<Setting
						title={LABELS.passwordLogin}
						control={
							<Switch
								aria-label={LABELS.passwordLogin}
								checked={draft.passwordLogin}
								disabled={passwordBlock !== null}
								onChange={(on) => set('passwordLogin', on)}
							/>
						}
						effect={
							draft.passwordLogin
								? `${consoleBucket ? 'Administrators' : 'People'} sign in with their email and a password. ${consoleBucket ? 'Password reset uses' : 'Password reset and self-service sign-up use'} this too.`
								: `${consoleBucket ? 'Administrators' : 'People'} sign in only through an identity provider; password reset${consoleBucket ? ' is' : ' and self-service sign-up are'} unavailable.`
						}
					>
						{passwordBlock && (
							<Typography.Text type="warning">
								{passwordBlock}{' '}
								{!consoleBucket && (
									<Link href={providersHref}>Identity providers →</Link>
								)}
							</Typography.Text>
						)}
						{baseline.passwordLogin &&
							!draft.passwordLogin &&
							(consoleBucket
								? readiness &&
									note(
										readiness.unlinkedAdministrators.length === 0
											? 'Every administrator has a linked identity.'
											: `These administrators have no linked identity and could no longer sign in: ${readiness.unlinkedAdministrators.map((a) => a.email).join(', ')}.`,
										'warning'
									)
								: counts?.withoutEnabledLink !== undefined &&
									note(
										`${counts.withoutEnabledLink.toLocaleString()} of ${plural(counts.users, 'user has', 'users have')} no account at an enabled identity provider and could no longer sign in.`,
										'warning'
									))}
						{baseline.passwordLogin &&
							!draft.passwordLogin &&
							countsUnavailable}
					</Setting>
					<Flex
						justify="space-between"
						align="center"
						gap={12}
						wrap
					>
						<div>
							<Typography.Text strong>Identity providers</Typography.Text>
							<br />
							<Typography.Text type="secondary">
								{contextLoading
									? '…'
									: enabled.length === 0
										? 'None enabled.'
										: `${String(enabled.length)} enabled: ${enabled.map((p) => p.displayName).join(', ')}${creating.length > 0 ? ` · ${plural(creating.length, 'creates', 'create')} accounts` : ''}`}
							</Typography.Text>
						</div>
						<Link href={providersHref}>Manage →</Link>
					</Flex>
					{/* Passkeys (plan 055) are a way to sign in and will be offered here once they exist. */}
				</Flex>
			</Card>

			<Card title="Second factor">
				<Setting
					title="Require an authenticator app for password sign-in"
					control={
						<Switch
							aria-label={LABELS.totpRequired}
							checked={draft.totpRequired}
							onChange={(on) => set('totpRequired', on)}
						/>
					}
					effect={
						draft.totpRequired
							? `Password sign-ins also ask for a 6-digit code. ${consoleBucket ? 'Administrators' : 'People'} without an authenticator set one up at their next sign-in. Provider sign-ins use the provider's own second factor.`
							: 'Password sign-ins need only the password. Anyone may still set up an authenticator.'
					}
				>
					{!draft.passwordLogin && (
						<Typography.Text type="warning">
							Has no effect while password sign-in is off.
						</Typography.Text>
					)}
					{!baseline.totpRequired &&
						draft.totpRequired &&
						draft.passwordLogin &&
						counts?.passwordWithoutAuthenticator !== undefined &&
						note(
							`${plural(counts.passwordWithoutAuthenticator, 'password user has', 'password users have')} no authenticator yet; they set one up at their next sign-in.`
						)}
					{!baseline.totpRequired && draft.totpRequired && countsUnavailable}
				</Setting>
			</Card>

			<Card title="Sign-up">
				<Setting
					title="Allow self-service sign-up"
					control={
						<Switch
							aria-label={LABELS.registrationOpen}
							checked={draft.registrationOpen}
							onChange={(on) => set('registrationOpen', on)}
						/>
					}
					effect={
						draft.registrationOpen
							? consoleBucket
								? 'Anyone who can reach the console sign-in page can create an administrator account. Each gets a personal team and nothing else.'
								: 'Anyone who can reach the sign-in page can create an account.'
							: consoleBucket
								? 'Administrator accounts are created by super administrators, or linked through an identity provider.'
								: 'Accounts are created by administrators, directories, and identity providers that create accounts.'
					}
				>
					{!consoleBucket && creating.length > 0 && (
						<Typography.Text type="secondary">
							Identity providers create accounts by their own setting, whatever
							this switch says.
						</Typography.Text>
					)}
					{!baseline.registrationOpen &&
						draft.registrationOpen &&
						(consoleBucket || defaultBucket) &&
						note(
							consoleBucket
								? 'Saving asks you to confirm: this opens the console to anyone who can reach it.'
								: "Saving asks you to confirm: the instance's own applications sign people in here.",
							'warning'
						)}
				</Setting>
			</Card>

			<Card title="Email verification">
				<Flex
					vertical
					gap={20}
				>
					<Setting
						title={LABELS.emailVerificationRequired}
						control={
							<Switch
								aria-label={LABELS.emailVerificationRequired}
								checked={draft.emailVerificationRequired}
								disabled={verificationBlock !== null}
								onChange={(on) => set('emailVerificationRequired', on)}
							/>
						}
						effect={
							draft.emailVerificationRequired
								? `Unverified ${people} are sent a message at their next sign-in and cannot continue until they follow it.`
								: consoleBucket
									? 'Administrators can sign in before they have verified their address.'
									: 'People can sign in before they have verified their address. Until they do, applications are told their address is not verified.'
						}
					>
						{verificationBlock && (
							<Flex
								gap={8}
								align="center"
								wrap
							>
								<Typography.Text type="warning">
									{verificationBlock}
								</Typography.Text>
								{mailReady && consoleBucket && !selfVerified && (
									<Button
										size="small"
										loading={sending}
										onClick={() => void onVerifySelf()}
									>
										Send me a verification email
									</Button>
								)}
							</Flex>
						)}
						{draft.emailVerificationRequired && !mailReady && (
							<Typography.Text type="warning">
								This server can&apos;t send email, so unverified {people} cannot
								receive the message.
							</Typography.Text>
						)}
						{!baseline.emailVerificationRequired &&
							draft.emailVerificationRequired &&
							counts &&
							note(
								`${plural(counts.unverified, consoleBucket ? 'administrator hasn’t' : 'user hasn’t', consoleBucket ? 'administrators haven’t' : 'users haven’t')} verified their address.`
							)}
						{!baseline.emailVerificationRequired &&
							draft.emailVerificationRequired &&
							countsUnavailable}
					</Setting>
					<Setting
						title="Method"
						control={
							<Segmented<'link' | 'code'>
								value={draft.verificationMethod}
								onChange={(value) => set('verificationMethod', value)}
								options={[
									{ label: 'Link in an email', value: 'link' },
									{ label: '6-digit code', value: 'code' }
								]}
							/>
						}
						effect={
							draft.verificationMethod === 'code'
								? 'The message carries a 6-digit code they type on the sign-in page.'
								: 'The message carries a link they follow from their inbox.'
						}
					/>
				</Flex>
			</Card>

			<SaveBar
				changes={changes}
				saving={saving}
				onSave={() => void save()}
				onDiscard={() => {
					setRefusal(null);
					setDraft(baseline);
				}}
			/>
		</Flex>
	);
}
