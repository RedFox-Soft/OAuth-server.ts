/*
 * The page's language for every component under the end-user theme. Provided by EndUserTheme, which wraps
 * every end-user tree on the server and in the hydrated client alike, so both sides read the same value and
 * no component needs the language threaded through its props.
 */

import { createContext, useContext } from 'react';

import type { Language } from './languages.js';

export const LanguageContext = createContext<Language>('en');

export function useLanguage(): Language {
	return useContext(LanguageContext);
}
