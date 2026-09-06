/*
 * Question sets, as data.
 *
 * One array feeds both the section a reader sees and the machine-readable description a search
 * engine or an assistant reads. That is the whole design: the two cannot disagree because there is
 * nothing to keep in step, and the guardrail's existing overclaim rule proves it on every build by
 * requiring every answer to appear in the rendered text.
 *
 * Two constraints on the writing, both load-bearing:
 *
 *  - The question is phrased as a person would ask it, not assembled from search terms. The visible
 *    copy is the constraint; if a question reads as keyword stuffing to a human it is wrong,
 *    whatever it does for a crawler.
 *  - The answer stands alone. An assistant will quote it without its question and without its page,
 *    so "Yes, with caveats" is a failure — the caveats have to be in the sentence.
 */

export interface QuestionAnswer {
	question: string;
	answer: string;
}

/* Migrated from an inline array on the pricing page, which rendered them but marked up none. */
export const PRICING_FAQ: readonly QuestionAnswer[] = [
	{
		question: 'Is it open?',
		answer:
			'FoxAuth is source-available, under FSL-1.1-ALv2. You may read, modify, self-host and redistribute the code, and build a business around it — the one thing you may not do is offer it to others as a competing hosted service. Two years after each version ships, that version converts to the Apache License 2.0, so the restriction expires on a published schedule rather than at our discretion.'
	},
	{
		question: 'Can I run it in production today?',
		answer:
			'Yes, self-hosted. The current release of FoxAuth is 0.1.0, and a 0.x version means the HTTP surface and the admin API may still change between minor releases; read the changelog before upgrading and re-run the setup script afterwards. The protocol endpoints follow the specs, so your clients are written against the RFC, not against us.'
	},
	{
		question: 'What does the cloud waitlist commit me to?',
		answer:
			'Nothing. We keep your address, mail you once when the managed FoxAuth instance opens, and delete it if you ask. There is no pricing to agree to yet.'
	},
	{
		question: 'Do you offer consulting?',
		answer:
			'Yes — integration work, threat modelling and profile conformance for regulated deployments of FoxAuth. Tell us the shape of the deployment and we will say whether we are the right people.'
	}
];
