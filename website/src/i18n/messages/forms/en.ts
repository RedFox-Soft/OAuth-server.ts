import { rich } from '../../types.ts';

/* The contact and enterprise forms. The address, the form endpoints and the subject are not here. */
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
				{ label: address, href },
				' and tell us about your deployment shape and the guarantees you need. We usually reply within two working days.'
			)
	},
	enterprise: {
		name: 'Your name',
		company: 'Company',
		users: 'How many people will sign in',
		usersPlaceholder: 'about 5,000 a month',
		hosting: 'Where should it run?',
		hostingOptions: {
			shared:
				'FoxAuth Enterprise Cloud, shared only by enterprise customers, with an SLA',
			ours: 'A dedicated instance run by FoxAuth, only for us',
			yours: 'On our own infrastructure, with your support',
			unsure: 'Not sure yet'
		},
		message: 'What do you need?',
		messagePlaceholder:
			'Your project, timeline, and why an instance of your own.',
		send: 'Request an invitation',
		reassurance: 'A real person replies, usually within two working days.',
		sent: 'Thank you. Your request is on its way, and a real person replies, usually within two working days.'
	}
};
