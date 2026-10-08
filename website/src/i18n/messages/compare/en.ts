import { rich } from '../../types.ts';

/*
 * The comparison index. The card text (title, description, bottom line) is not here: in English it
 * comes from each comparison's frontmatter, and in another language from messages/compareCards/.
 */
export default {
	title: 'Compare',
	description:
		'How FoxAuth compares with Keycloak and Auth0 on hosting, protocol coverage, administration and licensing, dated and sourced from their own documentation.',
	eyebrow: 'Compare',
	heading: 'Checked against their own documentation.',
	lead: 'Each comparison lists the pages we read and the date we read them. Where a product\'s documentation did not answer a question, the row says "not documented" instead of guessing.',
	shortVersion: {
		eyebrow: 'The short version',
		heading: 'Three questions decide it, and none of them is a feature count.',
		questions: [
			{
				question: 'Where does the data live?',
				answer:
					'In our experience this question settles most of them. A managed service holds your users on its infrastructure and bills you for them; FoxAuth holds them in a database you run and bills you for nothing. If a regulator, a contract or a procurement review requires identity data to stay in your own estate, the decision is already made and the rest of this page is detail.'
			},
			{
				question: 'What does the bill grow with?',
				answer:
					'Hosted identity is priced per monthly active user, which is cheap while you are small and is the reason most teams start looking. Self-hosting moves that cost to infrastructure and to the engineering time that keeps a server healthy. At scale that is usually a smaller bill, but it is a real one.'
			},
			{
				question: 'What does your team already run?',
				answer:
					'A team fluent in the JVM with a relational database probably has a shorter path to Keycloak than to anything else, whatever the protocol tables say. A team writing TypeScript has the opposite. Operational familiarity beats a feature comparison more often than anyone admits in a comparison table.'
			}
		],
		candour: rich(
			'Where FoxAuth is genuinely behind, the pages say so plainly: it has no SAML support and none planned, it is at a ',
			{ code: '0.x' },
			' release with an HTTP surface that may still change between minor versions, and it has none of the production hardening years of deployment buys. Where it is ahead, the rows say that too: the banking-grade profiles without a plan tier, and an AI agent administering the instance through the same audited path a human uses.'
		)
	},
	lastChecked: {
		before: 'Last checked ',
		after: (sources: number) => ` · ${sources} sources`
	}
};
