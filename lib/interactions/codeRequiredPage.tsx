import { Button, Card, Flex, Space, Typography } from 'antd';
import { buildUIPath } from './buildUIPath.js';
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
	logoSrc?: string;
	switcher?: SwitcherProps;
	face: SignInFace;
}

export function CodeRequiredPage({
	uid,
	variant,
	email = '',
	provider = '',
	logoSrc = DEFAULT_LOGO,
	switcher,
	face
}: CodeRequiredPageProps) {
	const T = SIGN_IN_TEXTS[useLanguage()].codeRequired;
	const app = face.app?.name;
	const service = face.service;
	const heading = app ? (
		<Message
			t={T.headingApp}
			values={{ app }}
		/>
	) : (
		T.headingAny
	);
	const providerVariant = variant === 'provider' || variant === 'providerAsk';

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
						{variant === 'setUp' && (
							<Button
								type="primary"
								block
								href={buildUIPath(uid, 'totp/enroll')}
							>
								{T.setUp}
							</Button>
						)}
						{variant === 'provider' && (
							<Button
								type="primary"
								block
								href={buildUIPath(uid, 'login')}
							>
								{T.passwordInstead}
							</Button>
						)}
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
