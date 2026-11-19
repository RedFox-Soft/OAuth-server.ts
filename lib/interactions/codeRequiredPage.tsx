import { Button, Card, Flex, Space, Typography } from 'antd';
import { buildUILoginPath, buildUIPath } from './buildUIPath.js';
import { NOTICE_PASSKEY } from './notices.js';
import { DEFAULT_LOGO } from './logo.js';
import { SignInMasthead, type SignInFace } from './signInMasthead.js';
import { foxVar } from '../html/theme/palette.js';
import { LanguageSwitch, type SwitcherProps } from './languageSwitch.js';
import { useLanguage } from '../i18n/context.js';
import { Message } from '../i18n/message.js';
import { SIGN_IN_TEXTS } from '../i18n/texts/signIn/index.js';

/*
 * The application requires a code from an authenticator app and this sign-in gave none (specs/127).
 *
 * A page of the sign-in rather than an error handed to the application: the person is in the middle of a task, and
 * what can help them depends on how they signed in, which only this server knows. Setting a code up continues this
 * same sign-in; a provider sign-in is told it cannot be used here, and offered a password where one would work;
 * every variant can go back to the application, which then hears `unmet_authentication_requirements` — and nothing on
 * the page promises what the application will show.
 *
 * The antd shell (wiki: interaction-page-families): it lives inside an interaction, carries the project's masthead and
 * the language switch, and its actions continue or end that interaction.
 */

export type CodeRequiredVariant =
	'setUp' | 'askOperators' | 'provider' | 'providerAsk';

export interface CodeRequiredPageProps {
	uid: string;
	variant: CodeRequiredVariant;
	/* The account's address, shown as itself so the person sees whose account this is. */
	email?: string;
	/* As the sign-in button names the provider; present for the provider variants. */
	provider?: string;
	/*
	 * An API that requires the code (specs/130), by the name its project declared: the heading names it, and the way
	 * back names no app, since the app the person came from is not the one asking.
	 */
	api?: string;
	/*
	 * In a project that accepts passkeys a passkey sign-in meets the requirement (specs/139): offered first when the
	 * account holds a passkey that still works here, after the page's own action otherwise. A link to this sign-in's
	 * page, where the passkey prompt lives; this page starts none.
	 */
	passkey?: 'primary' | 'secondary';
	logoSrc?: string;
	switcher?: SwitcherProps;
	face: SignInFace;
}

export function CodeRequiredPage({
	uid,
	variant,
	email = '',
	provider = '',
	api,
	passkey,
	logoSrc = DEFAULT_LOGO,
	switcher,
	face
}: CodeRequiredPageProps) {
	const T = SIGN_IN_TEXTS[useLanguage()].codeRequired;
	const app = api === undefined ? face.app?.name : undefined;
	const service = face.service;
	const asking = api ?? app;
	const heading = asking ? (
		<Message
			t={T.headingApp}
			values={{ app: asking }}
		/>
	) : (
		T.headingAny
	);
	const providerVariant = variant === 'provider' || variant === 'providerAsk';
	const passkeyFirst = passkey === 'primary';
	const passkeyLink = passkey && (
		<Button
			type={passkeyFirst ? 'primary' : 'default'}
			block
			href={buildUILoginPath(uid, NOTICE_PASSKEY)}
		>
			{T.passkey}
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
				<Typography.Paragraph>
					{providerVariant ? (
						<Message
							t={T.provider}
							values={{ provider }}
						/>
					) : (
						<Message
							t={T.noFactor}
							values={{ email }}
						/>
					)}
				</Typography.Paragraph>
				{passkeyFirst && (
					<Typography.Paragraph>
						{app ? (
							<Message
								t={T.passkeyHeldApp}
								values={{ email, app }}
							/>
						) : (
							<Message
								t={T.passkeyHeldAny}
								values={{ email }}
							/>
						)}
					</Typography.Paragraph>
				)}
				{variant === 'setUp' && (
					<Typography.Paragraph type="secondary">
						{T.setUpHint}
					</Typography.Paragraph>
				)}
				{(variant === 'askOperators' || variant === 'providerAsk') && (
					<Typography.Paragraph>
						<Message
							t={variant === 'askOperators' ? T.askOperators : T.providerAsk}
							values={{ service }}
						/>
					</Typography.Paragraph>
				)}
				<form
					method="post"
					action={buildUIPath(uid, 'code-required')}
				>
					<input
						type="hidden"
						name="action"
						value="return"
					/>
					<Space
						orientation="vertical"
						style={{ width: '100%' }}
						size={12}
					>
						{passkeyFirst && passkeyLink}
						{variant === 'setUp' && (
							<Button
								type={passkeyFirst ? 'default' : 'primary'}
								block
								href={buildUIPath(uid, 'totp/enroll')}
							>
								{T.setUp}
							</Button>
						)}
						{variant === 'provider' && (
							<Button
								type={passkeyFirst ? 'default' : 'primary'}
								block
								href={buildUIPath(uid, 'login')}
							>
								{T.passwordInstead}
							</Button>
						)}
						{!passkeyFirst && passkeyLink}
						<Button
							htmlType="submit"
							block
						>
							{app ? (
								<Message
									t={T.returnApp}
									values={{ app }}
								/>
							) : (
								T.returnAny
							)}
						</Button>
					</Space>
				</form>
				{switcher && <LanguageSwitch {...switcher} />}
			</Card>
		</Flex>
	);
}
