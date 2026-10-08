/*
 * Question sets, as data.
 *
 * One array feeds both the section a reader sees and the machine-readable description a search
 * engine or an assistant reads. That is the whole design: the two cannot disagree because there is
 * nothing to keep in step, and the guardrail's existing overclaim rule proves it on every build by
 * requiring every answer to appear in the rendered text.
 *
 * The arrays themselves live in the page's message module (the pricing questions in
 * src/i18n/messages/pricing/en.ts), so a translation changes the visible questions and the
 * structured data together.
 */

export interface QuestionAnswer {
	question: string;
	answer: string;
}
