import { rich } from '../../types.ts';

/* The contact and waitlist forms. The address, the Formspree endpoint and `_subject` are not here. */
export default {
	workEmail: 'Work email',
	emailPlaceholder: 'you@company.com',
	contact: {
		need: 'What do you need?',
		needPlaceholder:
			'Your deployment shape, timeline, and the guarantees you need.',
		send: 'Send',
		reassurance: 'A real person replies, usually within two working days.',
		fallback: (address: string, href: string) =>
			rich(
				'Email us at ',
				{ link: address, href },
				' and tell us about your deployment shape and the guarantees you need. We usually reply within two working days.'
			)
	},
	waitlist: {
		join: 'Join the waitlist',
		reassurance:
			'You’ll get one email when paid cloud plans open, and nothing else. No commitment.',
		fallback: (address: string, href: string) =>
			rich(
				'Email us at ',
				{ link: address, href },
				' to join the waitlist for paid cloud plans. You’ll get one email when they open, and joining commits you to nothing.'
			)
	}
};
