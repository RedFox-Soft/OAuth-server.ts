import type { ThemeConfig } from 'antd';

/*
 * The scope class antd's custom properties hang from. Fixed rather than derived from React's `useId`, because
 * the dark block (dark.tsx) names it in selectors that are written once and must match whatever page they
 * land on — server render and hydrated client alike.
 */
export const CSS_VAR_KEY = 'fox';

/*
 * antd's default palette falls short of WCAG AA in both schemes (specs/096 research R3): its blue is 4.1:1 as
 * text and under a white label, its error red 3.3:1, its secondary text 3.4:1, and a field's border 1.4:1
 * against the field. The owner chose to correct all of it. Each scheme carries its own overrides because the
 * dark algorithm re-derives colours from the seeds: a light-scheme blue fed to it comes out at 2.5:1.
 *
 * test/dark_theme/palette.spec.ts holds every value here to its minimum; change them against it.
 */
export const LIGHT_TOKENS: NonNullable<ThemeConfig['token']> = {
	colorPrimary: '#0958d9',
	colorPrimaryHover: '#1554ad',
	colorPrimaryActive: '#003eb3',
	colorLink: '#0958d9',
	colorLinkHover: '#003eb3',
	colorLinkActive: '#002c8c',
	colorError: '#cf1322',
	colorErrorHover: '#a8071a',
	colorErrorActive: '#820014',
	colorTextTertiary: 'rgba(0, 0, 0, 0.6)',
	colorTextDescription: 'rgba(0, 0, 0, 0.6)',
	colorTextPlaceholder: 'rgba(0, 0, 0, 0.6)',
	colorBorder: '#878787'
};

export const DARK_TOKENS: NonNullable<ThemeConfig['token']> = {
	colorPrimaryHover: '#1554ad',
	colorPrimaryActive: '#0d4ea6',
	colorLink: '#69b1ff',
	colorLinkHover: '#91caff',
	colorLinkActive: '#4096ff',
	colorError: '#c41d2a',
	colorErrorHover: '#a8071a',
	colorErrorActive: '#820014',
	colorErrorText: '#ff7875',
	colorErrorTextHover: '#ffa39e',
	colorTextTertiary: 'rgba(255, 255, 255, 0.5)',
	colorTextDescription: 'rgba(255, 255, 255, 0.5)',
	colorTextPlaceholder: 'rgba(255, 255, 255, 0.55)',
	colorBorder: '#7a7a7a'
};
