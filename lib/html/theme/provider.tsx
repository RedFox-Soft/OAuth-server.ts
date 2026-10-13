import type { ReactNode } from 'react';
import { ConfigProvider, theme } from 'antd';
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
 */
export function EndUserTheme({
	children,
	scheme = 'light',
	zeroRuntime = false
}: {
	children: ReactNode;
	scheme?: Scheme;
	zeroRuntime?: boolean;
}) {
	return (
		<ConfigProvider
			theme={{
				cssVar: { key: CSS_VAR_KEY },
				algorithm:
					scheme === 'dark' ? theme.darkAlgorithm : theme.defaultAlgorithm,
				token: scheme === 'dark' ? DARK_TOKENS : LIGHT_TOKENS,
				...(zeroRuntime ? { zeroRuntime: true } : {})
			}}
		>
			{children}
		</ConfigProvider>
	);
}
