import { Alert, Form, InputNumber, Radio, Select, Space } from 'antd';

import { secondStepWords } from '../signin/passkeysAccepted.js';

/*
 * An API's sign-in requirement (specs/130, specs/143): one level choice (any, two-step, or passkey), and a sign-in
 * every so often. The words are the application's own (specs/127, specs/142), and the text about apps is always there:
 * FoxAuth makes the requirement hold by refusing renewals and asking at the next sign-in, and what a person then sees
 * depends on the app they use.
 */

export const CLIENTS_PAGE =
	'https://foxauth.dev/docs/get-started/protect-an-mcp-server-at-your-proxy/#what-your-people-see-in-each-app';

export type SignInMethodLevel = 'any' | 'code' | 'passkey';
export type EveryChoice = 'off' | '1440' | '10080' | '20160' | 'custom';
export type EveryUnit = 'hours' | 'days';

export interface SignInFieldValues {
	signInLevel?: SignInMethodLevel;
	every?: EveryChoice;
	customAmount?: number;
	customUnit?: EveryUnit;
}

export function signInLevelOf(flags: {
	requireCode?: boolean;
	requirePasskey?: boolean;
}): SignInMethodLevel {
	if (flags.requirePasskey) return 'passkey';
	if (flags.requireCode) return 'code';
	return 'any';
}

export function signInFlagsOf(level: SignInMethodLevel): {
	requireCode: boolean;
	requirePasskey: boolean;
} {
	return {
		requireCode: level === 'code',
		requirePasskey: level === 'passkey'
	};
}

const EVERY_OPTIONS: { label: string; value: EveryChoice }[] = [
	{ label: 'Off', value: 'off' },
	{ label: 'Every day', value: '1440' },
	{ label: 'Every 7 days', value: '10080' },
	{ label: 'Every 14 days', value: '20160' },
	{ label: 'Custom', value: 'custom' }
];

/* The form's values for a stored interval in minutes. */
export function everyFields(
	minutes: number | null | undefined
): Pick<SignInFieldValues, 'every' | 'customAmount' | 'customUnit'> {
	if (minutes === null || minutes === undefined) return { every: 'off' };
	if (minutes === 1440 || minutes === 10080 || minutes === 20160) {
		return { every: String(minutes) as EveryChoice };
	}
	return minutes % 1440 === 0
		? { every: 'custom', customAmount: minutes / 1440, customUnit: 'days' }
		: { every: 'custom', customAmount: minutes / 60, customUnit: 'hours' };
}

/* The interval in minutes the form describes, or null for none. */
export function everyMinutes(values: SignInFieldValues): number | null {
	const every = values.every ?? 'off';
	if (every === 'off') return null;
	if (every !== 'custom') return Number(every);
	const amount = values.customAmount ?? 0;
	return values.customUnit === 'days' ? amount * 1440 : amount * 60;
}

/* "Sign in every day", "Sign in every 12 hours": the requirement in a word, for the APIs list and the API's Access tab. */
export function signInEveryText(minutes: number): string {
	if (minutes % 1440 === 0) {
		const days = minutes / 1440;
		return days === 1
			? 'Sign in every day'
			: `Sign in every ${String(days)} days`;
	}
	const hours = Math.round(minutes / 60);
	return hours === 1
		? 'Sign in every hour'
		: `Sign in every ${String(hours)} hours`;
}

export function ResourceSignInFields({
	checkedBy,
	level = 'any',
	every,
	passkeys = false
}: {
	checkedBy: 'server' | 'proxy';
	level?: SignInMethodLevel;
	every: EveryChoice | undefined;
	/* Whether the project accepts passkeys, which meet two-step and unlock the passkey level (specs/139, specs/143). */
	passkeys?: boolean;
}) {
	const levelExtra =
		level === 'passkey'
			? "Only people who sign in with a passkey can get a token for this API. People without a confirmed passkey are asked to create or confirm one; people who sign in through a provider, devices (TVs, consoles) and back-channel sign-ins can't connect."
			: level === 'code'
				? `A token for this API is issued only after a sign-in with ${secondStepWords(passkeys)}. People without an authenticator app are asked to set one up, if this project lets them; people who sign in through a provider can't connect.`
				: passkeys
					? 'Any sign-in to this project can get a token for this API.'
					: "Any sign-in to this project can get a token for this API. Turn on passkeys on the project's Sign-in tab to require a passkey.";
	return (
		<>
			<Form.Item
				name="signInLevel"
				label="How people must sign in"
				extra={levelExtra}
			>
				<Radio.Group
					optionType="button"
					options={[
						{ value: 'any', label: 'Any sign-in' },
						{ value: 'code', label: 'Two-step sign-in' },
						{
							value: 'passkey',
							label: 'Passkey',
							disabled: !passkeys && level !== 'passkey'
						}
					]}
				/>
			</Form.Item>
			<Form.Item
				label="Ask to sign in again every"
				extra="People reconnect their apps at least this often. People who sign in through a provider are asked by the provider; FoxAuth can't confirm they signed in again."
			>
				<Space wrap>
					<Form.Item
						name="every"
						noStyle
					>
						<Select
							options={EVERY_OPTIONS}
							style={{ width: 160 }}
						/>
					</Form.Item>
					{every === 'custom' && (
						<>
							<Form.Item
								name="customAmount"
								noStyle
								rules={[
									{ required: true, message: 'How often?' },
									({ getFieldValue }) => ({
										validator(_rule, value: number | undefined) {
											const minutes =
												getFieldValue('customUnit') === 'days'
													? (value ?? 0) * 1440
													: (value ?? 0) * 60;
											return minutes >= 60 && minutes <= 20160
												? Promise.resolve()
												: Promise.reject(new Error('From 1 hour to 14 days.'));
										}
									})
								]}
							>
								<InputNumber
									min={1}
									precision={0}
									style={{ width: 100 }}
								/>
							</Form.Item>
							<Form.Item
								name="customUnit"
								noStyle
							>
								<Select
									style={{ width: 110 }}
									options={[
										{ label: 'hours', value: 'hours' },
										{ label: 'days', value: 'days' }
									]}
								/>
							</Form.Item>
						</>
					)}
				</Space>
			</Form.Item>
			<Alert
				type="info"
				showIcon
				title="Not every app asks people to sign in again on its own"
				description={
					<>
						People are asked to sign in again inside their app, and not every
						app does this on its own. In Claude Code they reconnect the server
						in /mcp and ask again. In claude.ai they get a Connect card. ChatGPT
						and Codex may only show an error. Try it with the apps your people
						use before you rely on it.{' '}
						<a
							href={CLIENTS_PAGE}
							target="_blank"
							rel="noreferrer"
						>
							What people see in each app
						</a>
						<br />
						Apps that act for no one, and sign-ins by assertion (JWT bearer,
						identity assertions), can't connect.
						{checkedBy !== 'proxy' && (
							<>
								<br />
								Tokens issued before a change are refused only by your API's
								server, if it checks acr and auth_time in the token.
							</>
						)}
					</>
				}
			/>
		</>
	);
}
