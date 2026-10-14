import type { ReactNode } from 'react';
import { ConfigProvider, theme } from 'antd';
import type { Locale } from 'antd/es/locale/index.js';
import ruRU from 'antd/es/locale/ru_RU.js';
import zhCN from 'antd/es/locale/zh_CN.js';

import { LanguageContext } from '../../i18n/context.js';
import type { Language } from '../../i18n/languages.js';
import { CSS_VAR_KEY, DARK_TOKENS, LIGHT_TOKENS } from './tokens.js';

export type Scheme = 'light' | 'dark';

/*
 * The one antd theme every end-user page renders in (specs/096), on the server and in the hydrated client
 * alike — if the two disagreed on the key, the tokens or `zeroRuntime`, hydration would diverge in the browser
 * only. Pages always render in `light`; `dark` exists for dark.tsx, which renders the same tree a second time
 * to read the dark custom-property values off it.
 *
 * `zeroRuntime` is for the hydrated pages, which link the precompiled antd.css (see lib/html/zeroRuntime.tsx);
 * the terminal pages generate and inline their component CSS instead. The admin console keeps
 * lib/html/zeroRuntime.tsx and none of this.
 *
 * `language` sets antd's own words — the copy button's "Copy", for one — to the page's language (specs/097).
 * English is antd's built-in default, so it passes no locale object at all.
 */
// antd's locale modules are ES modules typed as CommonJS, so under `nodenext` the default import is typed as
// the module object while the runtime hands over the locale itself; this accepts either.
function antdLocale(imported: { default: Locale } | Locale): Locale {
	return 'default' in imported ? imported.default : imported;
}

const ANTD_LOCALES: Partial<Record<Language, Locale>> = {
	ru: antdLocale(ruRU),
	'zh-Hans': antdLocale(zhCN)
};

export function EndUserTheme({
	children,
	scheme = 'light',
	zeroRuntime = false,
	language = 'en'
}: {
	children: ReactNode;
	scheme?: Scheme;
	zeroRuntime?: boolean;
	language?: Language;
}) {
	return (
		<ConfigProvider
			locale={ANTD_LOCALES[language]}
			theme={{
				cssVar: { key: CSS_VAR_KEY },
				algorithm:
					scheme === 'dark' ? theme.darkAlgorithm : theme.defaultAlgorithm,
				token: scheme === 'dark' ? DARK_TOKENS : LIGHT_TOKENS,
				...(zeroRuntime ? { zeroRuntime: true } : {})
			}}
		>
			<LanguageContext.Provider value={language}>
				{children}
			</LanguageContext.Provider>
		</ConfigProvider>
	);
}
