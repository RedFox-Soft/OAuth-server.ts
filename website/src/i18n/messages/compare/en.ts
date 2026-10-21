import { rich } from '../../types.ts';

/*
 * The comparison index. The card text (title, description, bottom line) is not here: in English it
 * comes from each comparison's frontmatter, and in another language from messages/compareCards/.
 */
export default {
	title: 'Compare FoxAuth with Keycloak, Auth0 and others',
	description:
		'How FoxAuth compares with Keycloak, Auth0, Zitadel, authentik and Ory Hydra on hosting, protocols, administration and licensing, dated and sourced.',
	eyebrow: 'Compare',
	heading: "Checked against each product's own documentation.",
	lead: 'Each comparison lists the pages we read and the date we read them. Where a product\'s documentation did not answer a question, the row says "not documented". We do not guess.',
	shortVersion: {
		eyebrow: 'The short version',
		heading:
			'Three questions decide which server fits, and none of them is a feature count.',
		questions: [
			{
				question: 'Where does the data live?',
				answer:
					'In our experience this question settles most decisions. A managed service holds your users on its infrastructure and bills you for them; self-hosted FoxAuth holds them in a database you run and bills you for nothing. FoxAuth Cloud holds them on our infrastructure, and its free plan bills nothing. If a regulator, a contract or a procurement review requires identity data to stay in your own estate, the decision is already made and the rest of this page is detail.'
			},
			{
				question: 'What does the bill grow with?',
				answer:
					'Hosted identity is priced per monthly active user, which is cheap while you are small and is the reason most teams start looking for an alternative. Self-hosting moves that cost to infrastructure and to the engineering time that keeps a server healthy. At scale the self-hosting bill is usually smaller, but it is still a bill.'
			},
			{
				question: 'What does your team already run?',
				answer:
					'A team fluent in the JVM with a relational database probably has a shorter path to Keycloak than to anything else, whatever the protocol tables say. For a team writing TypeScript, Keycloak is the longer path. Operational familiarity outweighs a feature comparison more often than comparison tables suggest.'
			}
		],
		candour: rich(
			'Where FoxAuth is behind, the pages say so plainly: it has no SAML support and none planned; its first stable release, ',
			{ code: '1.0.0' },
			', came only in October 2026; and it lacks the production hardening that years of deployment bring. Where it is ahead, the rows say that too: the banking-grade profiles (DPoP, PAR, CIBA, mTLS, RAR and JARM) without a plan tier, and an AI agent administering the instance through the same audited path a human uses.'
		)
	},
	lastChecked: {
		before: 'Last checked ',
		after: (sources: number) => ` · ${sources} sources`
	}
};
