import { rich } from '../../types.ts';

export default {
	title: 'Contact',
	description:
		'Reach the FoxAuth team: general enquiries at hello@foxauth.dev, vulnerability reports at security@foxauth.dev, and bugs on GitHub.',
	eyebrow: 'Contact',
	heading: 'Three addresses, and one of them is a repository.',
	lead: 'Pick whichever fits what you have in hand. Bugs go to the tracker, vulnerabilities go to the security address, and everything else, from a deployment question to a support contract, comes to us through the form.',
	talk: {
		heading: 'Talk to us',
		body: 'Tell us the shape of the deployment you have in mind, ask about a support contract or consulting, or put the question the docs did not answer.'
	},
	vulnerability: {
		heading: 'Report a vulnerability',
		body: (address: string, href: string) =>
			rich(
				'Mail ',
				{ link: address, href },
				' and keep it off the public tracker. The security policy sets out what we do next and how long it takes.'
			),
		policy: 'Security policy'
	},
	bug: {
		heading: 'Report a bug',
		body: 'Open an issue with the version, the request and the response. Public issues tend to get fixed faster, because other people can confirm them.',
		issues: 'GitHub issues'
	}
};
