import { Alert, Typography } from 'antd';
import { humanDuration, throttleRate, type Values } from './model.js';

/*
 * Notes that state what a card's settings add up to, where the consequence is not legible from the
 * numbers themselves.
 *
 * Every setting on this page carries its own summary and its own long form, and for all but a few
 * that is enough. It is not enough where several settings combine into one figure an operator
 * actually cares about — they would have to read three descriptions and then do arithmetic, which
 * means in practice nobody knows what their configuration does.
 *
 * Keyed by group and gathered in one file on purpose. A note is by nature a special case; the
 * alternative was a branch inside GroupCard, which would have put per-setting knowledge into the
 * component that exists precisely to know nothing about individual settings. Adding the next one is
 * a case here and no change anywhere else.
 */
export function GroupNote({
	group,
	values
}: {
	group: string;
	values: Values;
}) {
	if (group === 'Login throttle') return <LoginThrottleNote values={values} />;
	return null;
}

/*
 * What the three throttle numbers cost an attacker.
 *
 * The window doubles from the first lockout and clamps at the ceiling, so with the shipped defaults
 * the ladder is 15 → 30 → 60 minutes and from the third lockout onward only the ceiling is in force.
 * That makes the ceiling — not the cap, and not the first window — the number that sets the settled
 * rate of a sustained attack, which is the opposite of how the three read on the page.
 *
 * Live rather than static: it recomputes as the operator edits, so the effect of a change is visible
 * before it is saved. Which matters here more than most places, because these settings are boot-only
 * — without this, the consequence of a change could not be seen until after a restart.
 */
function LoginThrottleNote({ values }: { values: Values }) {
	const rate = throttleRate(values);
	if (!rate) return null;

	return (
		<Alert
			type="info"
			showIcon
			style={{ marginBottom: 12 }}
			message={
				<span>
					About <strong>{rate.guessesPerDay.toLocaleString()}</strong> password
					guesses a day against one address, once its lockouts have escalated —{' '}
					{rate.cap} {rate.cap === 1 ? 'attempt' : 'attempts'} every{' '}
					{humanDuration(rate.ceilingSeconds)}.
				</span>
			}
			description={
				<Typography.Text
					type="secondary"
					style={{ fontSize: 12 }}
				>
					The longest lockout is what sets this rate; the first lockout only
					decides how long an honest mistake costs. A bucket that requires a
					one-time code stays at the first lockout however often it is tripped,
					because a guessed password there does not sign anyone in.
				</Typography.Text>
			}
		/>
	);
}
