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
		'FoxAuth pricing: start free on FoxAuth Cloud, or self-host the whole server for free. Paid cloud plans are in development, and enterprise support is available.',
	eyebrow: 'Pricing',
	heading: 'Free to start, in our cloud or on your own servers.',
	lead: 'Create a free account on FoxAuth Cloud and have a working authorization server in minutes. Or run the same server yourself, with every feature and no limits. Paid cloud plans, with higher limits and guarantees, are in development.',
	cloudFree: {
		badge: 'Available now',
		name: 'Cloud Free',
		price: 'Free',
		tagline: 'Our instance at auth.foxauth.dev. No card, no call.',
		items: [
			'2 projects per administrator, each its own OpenID Connect issuer',
			'1,000,000 monthly active users per project',
			'10 applications and 10 APIs per project',
			'Sign-in with Google, Apple, GitHub and Microsoft accounts of any organisation',
			'Machine-to-machine tokens, device sign-in, sender-constrained tokens (DPoP), pushed authorization requests (PAR), and administration by an AI agent over MCP',
			'Community support on GitHub issues; no SLA yet'
		],
		cta: 'Create a free account'
	},
	selfHosted: {
		badge: 'Available now',
		name: 'Self-hosted',
		price: 'Free',
		tagline: 'Your infrastructure, your database, no account with us.',
		items: [
			'Every feature, with no editions to choose between',
			'Unlimited users, projects, applications and tokens',
			'Source-available under FSL-1.1-ALv2',
			'Community support on GitHub issues'
		],
		cta: 'Get started'
	},
	cloud: {
		badge: 'In development',
		name: 'Cloud paid plans',
		price: 'Not priced yet',
		tagline: 'The same instance, with more room and someone on the hook.',
		items: [
			'Higher limits on projects, applications and users',
			'Sign-in through any OpenID provider, including one organisation’s Microsoft directory',
			'Your own project address and your own domain',
			'An SLA and a support address'
		]
	},
	enterprise: {
		badge: 'By agreement',
		name: 'Enterprise',
		price: 'Let’s talk',
		tagline: 'Self-hosted, with a support contract behind it.',
		items: [
			'You self-host; we support you',
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
				'FoxAuth is source-available under FSL-1.1-ALv2, which is not an open-source license. You may read, modify, self-host and redistribute the code, and build a business around it. The only thing you may not do is offer it to others as a competing hosted service. Two years after each version ships, that version converts to the Apache License 2.0, so the restriction expires on a published schedule with nothing left to our discretion.'
		},
		{
			question: 'Can I run FoxAuth in production today?',
			answer:
				'FoxAuth can run in production today, self-hosted. The free cloud plan has no SLA yet, so it is a place to start rather than one to depend on. The current release is 1.2.0. Since 1.0.0, the first stable release, the HTTP surface and the admin API change incompatibly only in a major release. Read the changelog before upgrading, take a backup when it names a migration that cannot be undone, and run the setup and migrate steps afterwards. The protocol endpoints follow the specs, so a client written for FoxAuth is in practice written against the RFC and should move to another server with little change.'
		},
		{
			question: 'Is the free cloud plan really free?',
			answer:
				'The free plan on FoxAuth Cloud costs nothing and asks for no card. It allows two projects per administrator, 1,000,000 monthly active users per project, ten applications and ten APIs per project, and sign-in through Google, Microsoft, Apple and GitHub. At the user cap only new sign-ups pause; nobody who already has an account is refused. The free plan has no SLA yet. Paid plans with higher limits and guarantees are in development; their waitlist commits you to nothing, and we email you once when they open.'
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
