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
		'Self-hosting FoxAuth is free and complete. A managed cloud instance is planned, and an enterprise support contract is available for self-hosted deployments.',
	eyebrow: 'Pricing',
	heading: 'Free to run. Paid only if you want us on the hook.',
	lead: 'There is one build of the server and it has every feature. What you can pay for is a managed instance or a support contract. No feature is held back for a paid tier.',
	selfHosted: {
		badge: 'Available now',
		name: 'Self-hosted',
		price: 'Free',
		tagline: 'Your infrastructure, your database, no account with us.',
		items: [
			'Every feature, with no editions to choose between',
			'Unlimited users, clients, projects and tokens',
			'Source-available under FSL-1.1-ALv2',
			'Community support on GitHub issues'
		],
		cta: 'Get started'
	},
	cloud: {
		badge: 'Coming soon',
		price: 'Not priced yet',
		tagline: 'The same server, run by the people who wrote it.',
		items: [
			'Managed instance on your own domain',
			'Backups and upgrades handled',
			'An SLA and a support address',
			'Your data stays in the region you pick'
		]
	},
	enterprise: {
		badge: 'By agreement',
		name: 'Enterprise',
		price: 'Let’s talk',
		tagline: 'Self-hosted, with a support contract behind it.',
		items: [
			'You self-host; we back you up',
			'Response-time SLA on defects',
			'Security advisories ahead of public disclosure',
			'Architecture review and priority fixes'
		]
	},
	faqEyebrow: 'Questions',
	faqHeading: 'The four we are asked every time.',
	faq: [
		{
			question: 'Is it open?',
			answer:
				'FoxAuth is source-available under FSL-1.1-ALv2. You may read, modify, self-host and redistribute the code, and build a business around it. The only thing you may not do is offer it to others as a competing hosted service. Two years after each version ships, that version converts to the Apache License 2.0, so the restriction expires on a published schedule with nothing left to our discretion.'
		},
		{
			question: 'Can I run it in production today?',
			answer:
				'FoxAuth can run in production today, self-hosted. The current release is 0.9.0, and a 0.x version means the HTTP surface and the admin API may still change between minor releases. Read the changelog before upgrading, take a backup when it names a migration that cannot be undone, and run the setup and migrate steps afterwards. The protocol endpoints follow the specs, so a client written for FoxAuth is in practice written against the RFC and should move to another server with little change.'
		},
		{
			question: 'What does the cloud waitlist commit me to?',
			answer:
				'The cloud waitlist commits you to nothing. We keep your address, mail you once when the managed FoxAuth instance opens, and delete it if you ask. There is no pricing to agree to yet.'
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
