import { useEffect, useRef, useState, useSyncExternalStore } from 'react';
import { Button, Card, Flex, Space, Typography } from 'antd';
import {
	browserSupportsWebAuthn,
	startRegistration,
	WebAuthnError,
	type PublicKeyCredentialCreationOptionsJSON
} from '@simplewebauthn/browser';
import { buildUIPath } from './buildUIPath.js';
import { DEFAULT_LOGO } from './logo.js';
import { SignInMasthead, type SignInFace } from './signInMasthead.js';
import { LanguageSwitch, type SwitcherProps } from './languageSwitch.js';
import { foxVar } from '../html/theme/palette.js';
import { useLanguage } from '../i18n/context.js';
import { Message } from '../i18n/message.js';
import { SIGN_IN_TEXTS } from '../i18n/texts/signIn/index.js';

/*
 * The offer of a passkey after a sign-in with a password (specs/141 contracts/sign-in-and-offer.md). The antd shell
 * (wiki: interaction-page-families): it lives inside the interaction and every action continues it.
 *
 * Creating a passkey needs the page's script; "Not now" and "Don't ask again" are plain forms, so a page without one
 * still lets the person on. A cancelled device dialog posts nothing: it is the same showing, and the person may try
 * again (FR-003). Where the passkey would be full at once, the browser is first asked to make it silently, from the
 * password it just filled in; any failure of that is the browser's business and shows nothing (research R8).
 */

export interface PasskeyOfferPageProps {
	uid: string;
	state: 'offer' | 'created';
	email: string;
	/* The creation options, present while the offer stands. */
	options?: PublicKeyCredentialCreationOptionsJSON;
	/* Try the browser's silent creation first: only for a passkey that is full at once. */
	silent?: boolean;
	/* "Don't ask again", from the second showing on (FR-004). */
	askNever?: boolean;
	/* The passkey made is conditional: the mail must be opened in this browser to confirm it. */
	conditional?: boolean;
	/* A refused create, as a sentence key. */
	refused?: 'failed' | 'exists';
	logoSrc?: string;
	switcher?: SwitcherProps;
	face: SignInFace;
}

function neverChanges(): () => void {
	return () => {};
}

function notOnTheServer(): boolean {
	return false;
}

export function PasskeyOfferPage({
	uid,
	state,
	email,
	options,
	silent = false,
	askNever = false,
	conditional = false,
	refused,
	logoSrc = DEFAULT_LOGO,
	switcher,
	face
}: PasskeyOfferPageProps) {
	const T = SIGN_IN_TEXTS[useLanguage()].passkeyOffer;
	const service = face.service;
	const app = face.app?.name;
	const action = buildUIPath(uid, 'passkey-offer');
	const form = useRef<HTMLFormElement>(null);
	const webAuthn = useSyncExternalStore(
		neverChanges,
		browserSupportsWebAuthn,
		notOnTheServer
	);
	const ready = state === 'offer' && options !== undefined && webAuthn;
	const [note, setNote] = useState<
		'cancelled' | 'exists' | 'failed' | undefined
	>(refused);

	const send = (credential: string, silently: boolean) => {
		const sending = form.current;
		if (!sending) return;
		const fields = sending.elements;
		const answer = fields.namedItem('credential');
		const quiet = fields.namedItem('silent');
		if (answer instanceof HTMLInputElement) answer.value = credential;
		if (quiet instanceof HTMLInputElement) quiet.disabled = !silently;
		sending.submit();
	};

	useEffect(() => {
		if (!ready || !silent) return;
		startRegistration({ optionsJSON: options, useAutoRegister: true })
			.then((made) => {
				send(JSON.stringify(made), true);
			})
			.catch(() => {
				/* No saved password, a passkey already here, or a browser without it: the ordinary offer stays. */
			});
	}, [ready, silent, options]);

	const create = () => {
		if (!ready) return;
		setNote(undefined);
		startRegistration({ optionsJSON: options })
			.then((made) => {
				send(JSON.stringify(made), false);
			})
			.catch((error: unknown) => {
				const code = error instanceof WebAuthnError ? error.code : undefined;
				setNote(
					code === 'ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED'
						? 'exists'
						: 'cancelled'
				);
			});
	};

	const continueLabel = app ? (
		<Message
			t={T.continueApp}
			values={{ app }}
		/>
	) : (
		T.continueAny
	);

	return (
		<Flex
			justify="center"
			style={{
				display: 'flex',
				minHeight: '100vh',
				alignItems: 'center',
				backgroundColor: foxVar('page')
			}}
		>
			<Card
				style={{
					width: 440,
					maxWidth: '100%',
					padding: 24,
					borderRadius: 12,
					boxShadow: `0 2px 8px ${foxVar('shadow')}`
				}}
			>
				<SignInMasthead
					face={face}
					logoSrc={logoSrc}
					heading={state === 'created' ? T.createdHeading : T.heading}
				/>
				{state === 'created' ? (
					<>
						<Typography.Paragraph>
							<Message
								t={conditional ? T.createdConditional : T.created}
								values={{ service, email }}
							/>
						</Typography.Paragraph>
						<form
							method="post"
							action={action}
						>
							<input
								type="hidden"
								name="action"
								value="continue"
							/>
							<Button
								type="primary"
								htmlType="submit"
								block
							>
								{continueLabel}
							</Button>
						</form>
					</>
				) : (
					<>
						<Typography.Paragraph>
							<Message
								t={T.explain}
								values={{ service, email }}
							/>
						</Typography.Paragraph>
						<Typography.Paragraph type="secondary">
							{T.where}
						</Typography.Paragraph>
						<form
							ref={form}
							method="post"
							action={action}
						>
							<input
								type="hidden"
								name="action"
								value="create"
							/>
							<input
								type="hidden"
								name="credential"
							/>
							<input
								type="hidden"
								name="silent"
								value="1"
								disabled
							/>
						</form>
						<Space
							orientation="vertical"
							style={{ width: '100%' }}
							size={12}
						>
							{note !== 'exists' && (
								<Button
									type="primary"
									block
									disabled={!ready}
									onClick={create}
								>
									{T.create}
								</Button>
							)}
							<noscript>
								<Typography.Text type="secondary">
									{T.needsScript}
								</Typography.Text>
							</noscript>
							{note && (
								<Typography.Text
									type="secondary"
									role="status"
								>
									{T[note]}
								</Typography.Text>
							)}
							<form
								method="post"
								action={action}
							>
								<input
									type="hidden"
									name="action"
									value="not_now"
								/>
								<Button
									type={note === 'exists' ? 'primary' : 'default'}
									htmlType="submit"
									block
								>
									{note === 'exists' ? continueLabel : T.notNow}
								</Button>
							</form>
							{askNever && (
								<form
									method="post"
									action={action}
									style={{ textAlign: 'center' }}
								>
									<input
										type="hidden"
										name="action"
										value="never"
									/>
									<Button
										type="link"
										htmlType="submit"
									>
										{T.never}
									</Button>
								</form>
							)}
						</Space>
					</>
				)}
				{switcher && <LanguageSwitch {...switcher} />}
			</Card>
		</Flex>
	);
}
