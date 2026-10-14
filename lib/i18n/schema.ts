/*
 * The stored form of a language, for the records that keep one (an interaction, an email-link challenge). A
 * separate module so the client bundle, which imports languages.ts, does not pull in TypeBox.
 */

import { Type as t } from '@sinclair/typebox';

export const LanguageSchema = t.Union([
	t.Literal('en'),
	t.Literal('ru'),
	t.Literal('zh-Hans')
]);

export const AlternativeLanguageSchema = t.Union([
	t.Literal('ru'),
	t.Literal('zh-Hans')
]);
