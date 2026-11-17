/*
 * The FAQ array feeds both the visible questions and the page's FAQPage structured data, so a
 * translation changes both at once. Two constraints on the writing, both load-bearing:
 *
 *  - The question is phrased as a person would ask it, not assembled from search terms. The visible
 *    copy is the constraint; if a question reads as keyword stuffing to a human it is wrong,
 *    whatever it does for a crawler.
 *  - The answer stands alone. An assistant will quote it without its question and without its page,
 *    so "Yes, with caveats" is a failure — the caveats have to be in the sentence.
 */
export default {
	title: 'Pricing',
	description:
		'FoxAuth Cloud is free during the beta, with no limit on users. Enterprise, an instance of your own, is by invitation.',
	eyebrow: 'Pricing',
	heading: 'Free in our cloud. An instance of your own by invitation.',
	lead: 'FoxAuth Cloud is free during the beta, with no limit on users: create an account and have a working authorization server in minutes. Teams that join during the beta keep it free for a year after paid plans launch. A company that needs an instance of its own asks for an invitation.',
	cloudFree: {
		badge: 'Free during the beta',
		name: 'Cloud',
		price: 'Free',
		tagline:
			'Our instance at auth.foxauth.dev. No card, no call, no user limit.',
		items: [
			'No limit on monthly active users, applications or APIs',
			'Up to 10 projects per administrator, each its own OpenID Connect issuer at an address you choose',
			'Sign-in with Google, Apple, GitHub and Microsoft, and through any OpenID provider, including Okta or one organisation’s Entra ID',
			'Machine-to-machine tokens, device sign-in, sender-constrained tokens (DPoP), pushed authorization requests (PAR), and administration by an AI agent over MCP',
			'Your own domain on request',
			'Free for a year after paid plans launch, for teams that join during the beta',
			'Community support on GitHub issues; no SLA yet'
		],
		cta: 'Create a free account'
	},
	enterprise: {
		badge: 'By invitation',
		name: 'Enterprise',
		price: 'Let’s talk',
		tagline:
			'An Enterprise Cloud apart from the free one, an instance of your own, or your infrastructure. By invitation only.',
		items: [
			'Enterprise Cloud: shared only by enterprise customers, apart from the free cloud, with an SLA',
			'A dedicated instance, run by us or on your infrastructure, its database and keys apart from everyone else’s',
			'Response-time SLA on defects',
			'Security advisories ahead of public disclosure',
			'Architecture review and priority fixes'
		]
	},
	faqEyebrow: 'Questions',
	faqHeading:
		'The four questions we are asked every time: the license, production use, the free plan and consulting.',
	faq: [
		{
			question: 'Is FoxAuth open source?',
			answer:
				'FoxAuth is source-available under FSL-1.1-ALv2, which is not an open-source license. You may read, modify, self-host and redistribute the code, and build a business around it. The only thing you may not do is offer it to others in a commercial product or service that competes with FoxAuth, hosted or not. Two years after each version ships, that version converts to the Apache License 2.0, so the restriction expires on a published schedule with nothing left to our discretion.'
		},
		{
			question: 'Can I run FoxAuth in production today?',
			answer:
				'FoxAuth can run in production today, self-hosted. The free cloud plan has no SLA yet, so it is a place to start rather than one to depend on. The current release is 2.0.1. Since 1.0.0, the first stable release, the HTTP surface and the admin API change incompatibly only in a major release. Read the changelog before upgrading, take a backup when it names a migration that cannot be undone, and run the setup and migrate steps afterwards. The protocol endpoints follow the specs, so a client written for FoxAuth is in practice written against the RFC and should move to another server with little change.'
		},
		{
			question: 'Is FoxAuth Cloud really free?',
			answer:
				'FoxAuth Cloud is free during the beta and asks for no card. There is no limit on monthly active users, applications or APIs, and it includes up to ten projects per administrator, an address you choose for each, and sign-in through any OpenID provider. The few features that need a super administrator, such as developers registering their own apps, run only on your own server. Your own domain is set up on request. Teams that join during the beta keep it free for a year after paid plans launch. There is no SLA yet. Paid plans with an SLA are in development.'
		},
		{
			question: 'Do you offer consulting?',
			answer:
				'We offer consulting on FoxAuth: integration work, threat modelling and profile conformance for regulated deployments. Tell us the shape of yours and we will say whether we are the right people.'
		}
	],
	readLicense: 'Read the license',
	contactUs: 'Contact us'
};
