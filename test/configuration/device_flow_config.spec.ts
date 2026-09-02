import { describe, it, expect } from 'bun:test';
import { validateConfiguration } from 'lib/configs/configuration.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { generate } from 'lib/helpers/user_codes.ts';

/*
 * The device flow's user-code mask, tested against the pure validator — the single definition the
 * administrative PUT reaches through validateEffectiveConfig, so what is pinned here is what a
 * super-admin cannot persist.
 *
 * The mask is a template in which `*` is replaced by a random character from the charset and every
 * other character is copied through verbatim (helpers/user_codes.ts). That makes the number of
 * asterisks the entire entropy of the code, and a mask with none of them a code that is the same for
 * every pairing — which is why zero is refused here rather than merely discouraged.
 */
const withMask = (mask: unknown) => ({
	...ApplicationConfig,
	'deviceFlow.enabled': true,
	'deviceFlow.mask': mask
});

describe('deviceFlow mask validation', () => {
	it('accepts the shipped defaults', () => {
		expect(() => validateConfiguration({ ...ApplicationConfig })).not.toThrow();
	});

	it('accepts a mask with asterisks and permitted separators', () => {
		for (const mask of ['****-****', '*** *** ***', '********', '*']) {
			expect(() => validateConfiguration(withMask(mask))).not.toThrow();
		}
	});

	it('still refuses characters outside asterisk, hyphen and space', () => {
		expect(() => validateConfiguration(withMask('0000-0000'))).toThrow(
			/asterisk/
		);
		expect(() => validateConfiguration(withMask('abcd'))).toThrow(/asterisk/);
	});

	/*
	 * The case this spec was written for. Each of these passes the character check — they contain
	 * nothing but permitted characters — and each produces a user code with no random part at all.
	 */
	describe('a mask with no random part', () => {
		const noEntropy = ['', '-', '---', '-  -', ' '];

		for (const mask of noEntropy) {
			it(`refuses ${JSON.stringify(mask)}`, () => {
				expect(() => validateConfiguration(withMask(mask))).toThrow(
					/at least one asterisk/
				);
			});
		}

		/*
		 * Why it matters, demonstrated rather than asserted in prose: the generator copies every
		 * non-asterisk character through, so without one the "generated" code is the mask itself and is
		 * identical for every device that ever pairs. Guessing it is not an attack, it is reading the
		 * configuration.
		 */
		it('would otherwise hand every device the same code', () => {
			for (const mask of noEntropy) {
				expect(generate('base-20', mask)).toBe(mask);
			}
			expect(generate('base-20', '****-****')).not.toBe('****-****');
		});
	});

	/*
	 * Scoped to the flow being on, deliberately, and this pins the choice.
	 *
	 * The mask's character check already sits inside that guard, and widening either check to a
	 * disabled flow would refuse a boot that succeeds today — a deployment carrying a junk mask it
	 * never uses would stop starting, which is a bigger change than this fix is entitled to make.
	 *
	 * It closes the hole anyway, because the check fires at the moment the value starts to matter: the
	 * administrative PUT validates the *merged* configuration, so the submission that switches the flow
	 * on is refused while the stored mask cannot generate a code. An operator therefore cannot reach a
	 * running server that issues a constant user code, which is the property that matters — as opposed
	 * to never being able to store the string.
	 */
	it('accepts an entropy-free mask while the flow is off, and refuses the switch-on', () => {
		expect(() =>
			validateConfiguration({
				...ApplicationConfig,
				'deviceFlow.enabled': false,
				'deviceFlow.mask': '---'
			})
		).not.toThrow();

		expect(() =>
			validateConfiguration({
				...ApplicationConfig,
				'deviceFlow.enabled': true,
				'deviceFlow.mask': '---'
			})
		).toThrow(/at least one asterisk/);
	});
});
