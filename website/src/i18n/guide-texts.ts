import type { LocaleKey } from '../data/seo.ts';
import type { DocsExport } from '../data/export.ts';

/*
 * The words of the "What do you need?" guide in one language. English is built from the docs export
 * (it is declared in lib/consts/situation_guide.ts, where the console reads it too); Russian and
 * Chinese live in messages/guideSituations/<locale>.ts, keyed by id. Prompts are not here: they stay
 * English in every language.
 */

export type GuideActor = 'person' | 'program' | 'agent';

export interface GuideQuestionTexts {
	title: string;
	sub: string;
	second: string;
	answers: Record<string, { title: string; sub: string }>;
}

export interface GuideSituationTexts {
	title: string;
	sentence: string;
	protocol?: string;
	/* The words under the two pictures: what is wrong without FoxAuth, and what it changes. */
	problemCaption: string;
	fixCaption: string;
	lanes: Record<string, string>;
	steps: { label: string; text: string }[];
	sees: string[];
	goodToKnow: string[];
	actionLabel?: string;
}

export interface GuideTexts {
	questions: Record<GuideActor, GuideQuestionTexts>;
	situations: Record<string, GuideSituationTexts>;
}

type GuideExport = DocsExport['situationGuide'];

interface GuideModule {
	default: unknown;
	source?: string;
}

const modules: Partial<Record<string, GuideModule>> =
	import.meta.glob<GuideModule>('./messages/guideSituations/*.ts', {
		eager: true
	});

export function guideTextsFromExport(exported: GuideExport): GuideTexts {
	const questions = {} as Record<GuideActor, GuideQuestionTexts>;
	for (const question of exported.questions) {
		questions[question.actor] = {
			title: question.title,
			sub: question.sub,
			second: question.second,
			answers: Object.fromEntries(
				question.answers.map((a) => [a.answer, { title: a.title, sub: a.sub }])
			)
		};
	}
	const situations: Record<string, GuideSituationTexts> = {};
	for (const situation of exported.situations) {
		situations[situation.id] = {
			title: situation.title,
			sentence: situation.sentence,
			protocol: situation.protocol,
			problemCaption: situation.problem.caption,
			fixCaption: situation.fixCaption,
			lanes: Object.fromEntries(situation.lanes.map((l) => [l.id, l.label])),
			steps: situation.steps.map((s) => ({ label: s.label, text: s.text })),
			sees: situation.sees.lines,
			goodToKnow: situation.goodToKnow,
			...(situation.action.label ? { actionLabel: situation.action.label } : {})
		};
	}
	return { questions, situations };
}

function sameLength(
	id: string,
	field: string,
	english: readonly unknown[],
	translated: readonly unknown[] | undefined,
	locale: LocaleKey
): void {
	if (!translated || translated.length !== english.length) {
		throw new Error(
			`guideSituations/${locale}: situation "${id}" has ${translated?.length ?? 0} ${field} where English has ${english.length}`
		);
	}
}

/*
 * The guide's texts in a language. A translation that lacks an id, or whose lists differ in length
 * from English, throws naming the situation and the field: `satisfies` cannot see list lengths, and a
 * guide that silently says less than the English one is the failure this prevents.
 */
export function guideTextsFor(
	locale: LocaleKey,
	exported: GuideExport
): GuideTexts {
	const english = guideTextsFromExport(exported);
	if (locale === 'en') return english;

	const module = modules[`./messages/guideSituations/${locale}.ts`];
	if (!module) {
		throw new Error(
			`src/i18n/messages/guideSituations/${locale}.ts is missing; every published language needs it`
		);
	}
	/* Read as possibly incomplete: the checks below are what make it a GuideTexts. */
	const texts = module.default as {
		questions?: Partial<Record<GuideActor, Partial<GuideQuestionTexts>>>;
		situations?: Partial<Record<string, Partial<GuideSituationTexts>>>;
	};

	for (const [actor, question] of Object.entries(english.questions)) {
		const translated = texts.questions?.[actor as GuideActor];
		if (!translated) {
			throw new Error(
				`guideSituations/${locale}: question "${actor}" is missing`
			);
		}
		for (const answer of Object.keys(question.answers)) {
			if (!translated.answers?.[answer]) {
				throw new Error(
					`guideSituations/${locale}: question "${actor}" has no answer "${answer}"`
				);
			}
		}
	}

	for (const [id, base] of Object.entries(english.situations)) {
		const translated = texts.situations?.[id];
		if (!translated) {
			throw new Error(
				`guideSituations/${locale}: situation "${id}" is missing`
			);
		}
		for (const field of ['problemCaption', 'fixCaption'] as const) {
			if (!translated[field]) {
				throw new Error(
					`guideSituations/${locale}: situation "${id}" has no ${field}`
				);
			}
		}
		for (const lane of Object.keys(base.lanes)) {
			if (!translated.lanes?.[lane]) {
				throw new Error(
					`guideSituations/${locale}: situation "${id}" has no lane "${lane}"`
				);
			}
		}
		sameLength(id, 'steps', base.steps, translated.steps, locale);
		sameLength(id, 'sees', base.sees, translated.sees, locale);
		sameLength(
			id,
			'goodToKnow',
			base.goodToKnow,
			translated.goodToKnow,
			locale
		);
		if (base.actionLabel && !translated.actionLabel) {
			throw new Error(
				`guideSituations/${locale}: situation "${id}" has no actionLabel`
			);
		}
	}
	return texts as GuideTexts;
}
