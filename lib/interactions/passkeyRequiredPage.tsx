import { useRef, useState, useSyncExternalStore } from 'react';
import { Button, Card, Flex, Space, Typography } from 'antd';
import {
	browserSupportsWebAuthn,
	startRegistration,
	WebAuthnError,
	type PublicKeyCredentialCreationOptionsJSON
} from '@simplewebauthn/browser';
import { buildUILoginPath, buildUIPath } from './buildUIPath.js';
import { NOTICE_PASSKEY } from './notices.js';
import { DEFAULT_LOGO } from './logo.js';
import { SignInMasthead, type SignInFace } from './signInMasthead.js';
import { LanguageSwitch, type SwitcherProps } from './languageSwitch.js';
import { foxVar } from '../html/theme/palette.js';
import { useLanguage } from '../i18n/context.js';
import { Message } from '../i18n/message.js';
import { SIGN_IN_TEXTS } from '../i18n/texts/signIn/index.js';

/*
 * An application requires a passkey and this sign-in was not one (specs/142 contracts/sign-in-and-refusal.md). Served
 * at the two-step page's address, as one more reason a sign-in was not enough for an app, and like that page it leads
 * to the goal: the one step that gets the person in from where they stand, and always the way back to the app.
 *
 * The antd shell (wiki: interaction-page-families). Creating a passkey needs the page's script, as on the offer page;
 * the passkey made follows the offer's rules (full after a code, conditional after a password alone), and signing in
 * with it is what meets the requirement: creating one never raises the sign-in in progress.
 */

export type PasskeyRequiredVariant =
	| 'passkeySignIn'
	| 'passkeyConfirm'
	| 'passkeyCreate'
	| 'passkeyAsk'
	| 'device';

export interface PasskeyRequiredPageProps {
	uid: string;
	requirement: 'passkey';
	variant: PasskeyRequiredVariant;
	email?: string;
	/* The creation options, for `passkeyCreate`. */
	options?: PublicKeyCredentialCreationOptionsJSON;
	/* A passkey just made on this page: full, or conditional and waiting for its mail. */
	created?: 'full' | 'conditional';
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

export function PasskeyRequiredPage({
	uid,
	variant,
	email = '',
	options,
	created,
	refused,
	logoSrc = DEFAULT_LOGO,
	switcher,
	face
}: PasskeyRequiredPageProps) {
	const T = SIGN_IN_TEXTS[useLanguage()].passkeyRequired;
	const back = SIGN_IN_TEXTS[useLanguage()].codeRequired;
	const app = face.app?.name;
	const service = face.service;
	const action = buildUIPath(uid, 'code-required');
	const form = useRef<HTMLFormElement>(null);
	const webAuthn = useSyncExternalStore(
		neverChanges,
		browserSupportsWebAuthn,
		notOnTheServer
	);
	const ready =
		variant === 'passkeyCreate' && options !== undefined && webAuthn;
	const [note, setNote] = useState<
		'cancelled' | 'exists' | 'failed' | undefined
	>(refused);

	const create = () => {
		if (!ready) return;
		setNote(undefined);
		startRegistration({ optionsJSON: options })
			.then((made) => {
				const sending = form.current;
				const answer = sending?.elements.namedItem('credential');
				if (!sending || !(answer instanceof HTMLInputElement)) return;
				answer.value = JSON.stringify(made);
				sending.submit();
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

	const heading = app ? (
		<Message
			t={T.headingApp}
			values={{ app }}
		/>
	) : (
		T.headingAny
	);
	const signIn = (
		<Button
			type="primary"
			block
			href={buildUILoginPath(uid, NOTICE_PASSKEY)}
		>
			{T.signIn}
		</Button>
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
					heading={heading}
				/>
				<Typography.Paragraph>{T.explain}</Typography.Paragraph>
				<Typography.Paragraph>
					{created === 'full' ? (
						T.createdFull
					) : created === 'conditional' ? (
						<Message
							t={T.createdConditional}
							values={{ email }}
						/>
					) : variant === 'passkeySignIn' ? (
						<Message
							t={T.held}
							values={{ email }}
						/>
					) : variant === 'passkeyConfirm' ? (
						T.notConfirmed
					) : variant === 'device' ? (
						T.device
					) : (
						<Message
							t={T.none}
							values={{ email }}
						/>
					)}
				</Typography.Paragraph>
				{variant === 'passkeyAsk' && (
					<Typography.Paragraph>
						<Message
							t={T.ask}
							values={{ service }}
						/>
					</Typography.Paragraph>
				)}
				{variant === 'passkeyCreate' && (
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
					</form>
				)}
				<Space
					orientation="vertical"
					style={{ width: '100%' }}
					size={12}
				>
					{(variant === 'passkeySignIn' || variant === 'passkeyConfirm') &&
						signIn}
					{variant === 'passkeyCreate' && note !== 'exists' && (
						<Button
							type="primary"
							block
							disabled={!ready}
							onClick={create}
						>
							{T.create}
						</Button>
					)}
					{variant === 'passkeyCreate' && (
						<noscript>
							<Typography.Text type="secondary">
								{T.needsScript}
							</Typography.Text>
						</noscript>
					)}
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
							value="return"
						/>
						<Button
							htmlType="submit"
							block
						>
							{app ? (
								<Message
									t={back.returnApp}
									values={{ app }}
								/>
							) : (
								back.returnAny
							)}
						</Button>
					</form>
				</Space>
				{switcher && <LanguageSwitch {...switcher} />}
			</Card>
		</Flex>
	);
}
