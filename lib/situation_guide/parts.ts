import type { GuidePart, ProblemMark } from '../consts/situation_guide.js';

/*
 * The drawings of the guide's pictures, drawn for this project on a 24-unit grid. Each path is meant to be stroked
 * 2 units wide in `currentColor`, with round caps and joins and no fill, so one drawing serves both themes and every
 * size. Path data only, and import-free beyond the types, because the console's browser bundle loads this module and
 * the site receives it through the docs export: neither page keeps a drawing of its own.
 */

export interface Glyph {
	viewBox: string;
	paths: string[];
}

const GRID = '0 0 24 24';

export const GUIDE_PARTS: Readonly<Record<GuidePart, Glyph>> = {
	person: {
		viewBox: GRID,
		paths: [
			'M8.25 8a3.75 3.75 0 1 0 7.5 0a3.75 3.75 0 1 0 -7.5 0',
			'M4.75 20.25c0-4 3.25-6.75 7.25-6.75s7.25 2.75 7.25 6.75'
		]
	},
	laptop: {
		viewBox: GRID,
		paths: [
			'M6 4.5h12a2 2 0 0 1 2 2v7.5a2 2 0 0 1 -2 2h-12a2 2 0 0 1 -2 -2v-7.5a2 2 0 0 1 2 -2z',
			'M2 19.5h20'
		]
	},
	browser: {
		viewBox: GRID,
		paths: [
			'M5.25 4h13.5a2.5 2.5 0 0 1 2.5 2.5v11a2.5 2.5 0 0 1 -2.5 2.5h-13.5a2.5 2.5 0 0 1 -2.5 -2.5v-11a2.5 2.5 0 0 1 2.5 -2.5z',
			'M2.75 8.75h18.5',
			'M5.75 6.4h.01M8.25 6.4h.01',
			'M7 12.75h6M7 15.75h9'
		]
	},
	server: {
		viewBox: GRID,
		paths: [
			'M5.5 3.25h13a2 2 0 0 1 2 2v3.5a2 2 0 0 1 -2 2h-13a2 2 0 0 1 -2 -2v-3.5a2 2 0 0 1 2 -2z',
			'M5.5 13.25h13a2 2 0 0 1 2 2v3.5a2 2 0 0 1 -2 2h-13a2 2 0 0 1 -2 -2v-3.5a2 2 0 0 1 2 -2z',
			'M7.25 7h.01M7.25 17h.01M11 7h5.5M11 17h5.5'
		]
	},
	phone: {
		viewBox: GRID,
		paths: [
			'M9 2.5h6a2.5 2.5 0 0 1 2.5 2.5v14a2.5 2.5 0 0 1 -2.5 2.5h-6a2.5 2.5 0 0 1 -2.5 -2.5v-14a2.5 2.5 0 0 1 2.5 -2.5z',
			'M10.75 18.5h2.5'
		]
	},
	tv: {
		viewBox: GRID,
		paths: [
			'M4.5 4h15a2 2 0 0 1 2 2v8.5a2 2 0 0 1 -2 2h-15a2 2 0 0 1 -2 -2v-8.5a2 2 0 0 1 2 -2z',
			'M8 20.75h8M12 16.5v4.25'
		]
	},
	clock: {
		viewBox: GRID,
		paths: ['M3.5 12a8.5 8.5 0 1 0 17 0a8.5 8.5 0 1 0 -17 0', 'M12 7.5V12l3 2']
	},
	agent: {
		viewBox: GRID,
		paths: [
			'M7 8h10a3 3 0 0 1 3 3v6a3 3 0 0 1 -3 3h-10a3 3 0 0 1 -3 -3v-6a3 3 0 0 1 3 -3z',
			'M12 8V5.25',
			'M10.75 3.75a1.25 1.25 0 1 0 2.5 0a1.25 1.25 0 1 0 -2.5 0',
			'M9 13.25v1.5M15 13.25v1.5',
			'M2 12.75v2.5M22 12.75v2.5'
		]
	},
	api: {
		viewBox: GRID,
		paths: [
			'M5.75 3.75h12.5a3 3 0 0 1 3 3v10.5a3 3 0 0 1 -3 3h-12.5a3 3 0 0 1 -3 -3v-10.5a3 3 0 0 1 3 -3z',
			'M9.75 8.25c-1.6 0-2.1.6-2.1 1.7v.6c0 .8-.45 1.45-1.15 1.45.7 0 1.15.65 1.15 1.45v.6c0 1.1.5 1.7 2.1 1.7M14.25 8.25c1.6 0 2.1.6 2.1 1.7v.6c0 .8.45 1.45 1.15 1.45-.7 0-1.15.65-1.15 1.45v.6c0 1.1-.5 1.7-2.1 1.7'
		]
	},
	company: {
		viewBox: GRID,
		paths: [
			'M4.5 20.75V5a1.75 1.75 0 0 1 1.75-1.75h6.5A1.75 1.75 0 0 1 14.5 5v15.75',
			'M14.5 9h3.25a1.75 1.75 0 0 1 1.75 1.75v10',
			'M2.75 20.75h18.5M8 7.25h3M8 10.75h3M8 14.25h3M10 20.75v-3'
		]
	},
	directory: {
		viewBox: GRID,
		paths: [
			'M10 3h4a1 1 0 0 1 1 1v3a1 1 0 0 1 -1 1h-4a1 1 0 0 1 -1 -1v-3a1 1 0 0 1 1 -1z',
			'M4 16h4a1 1 0 0 1 1 1v3a1 1 0 0 1 -1 1h-4a1 1 0 0 1 -1 -1v-3a1 1 0 0 1 1 -1z',
			'M16 16h4a1 1 0 0 1 1 1v3a1 1 0 0 1 -1 1h-4a1 1 0 0 1 -1 -1v-3a1 1 0 0 1 1 -1z',
			'M12 8v4M6 16v-4h12v4'
		]
	},
	fox: {
		viewBox: GRID,
		paths: [
			'M12 2.5l7.75 3v6.1c0 4.7-3.3 8.4-7.75 10.15C7.55 20 4.25 16.3 4.25 11.6V5.5z',
			'M8.4 8.2l1.7 2.05h3.8l1.7-2.05v3.55c0 1.9-1.6 3.45-3.6 4.45-2-1-3.6-2.55-3.6-4.45z'
		]
	},
	cloud: {
		viewBox: GRID,
		paths: [
			'M7.25 18.5a4.25 4.25 0 0 1-.6-8.46 5.75 5.75 0 0 1 11.06-1.2A4.85 4.85 0 0 1 17.25 18.5z'
		]
	},
	mail: {
		viewBox: GRID,
		paths: [
			'M5 5h14a2 2 0 0 1 2 2v10a2 2 0 0 1 -2 2h-14a2 2 0 0 1 -2 -2v-10a2 2 0 0 1 2 -2z',
			'M3.5 6.5l8.5 6.5 8.5-6.5'
		]
	},
	authenticator: {
		viewBox: GRID,
		paths: [
			'M9 2.5h6a2.5 2.5 0 0 1 2.5 2.5v14a2.5 2.5 0 0 1 -2.5 2.5h-6a2.5 2.5 0 0 1 -2.5 -2.5v-14a2.5 2.5 0 0 1 2.5 -2.5z',
			'M15 10.5a3 3 0 1 1-3-3',
			'M12 7.5v3h3',
			'M10.75 18.5h2.5'
		]
	},
	globe: {
		viewBox: GRID,
		paths: [
			'M3 12a9 9 0 1 0 18 0a9 9 0 1 0 -18 0',
			'M3 12h18',
			'M12 3c-3.5 3-3.5 15 0 18M12 3c3.5 3 3.5 15 0 18'
		]
	},
	team: {
		viewBox: GRID,
		paths: [
			'M5.5 8a3.5 3.5 0 1 0 7 0a3.5 3.5 0 1 0 -7 0',
			'M2.5 20c0-3.6 2.9-6.5 6.5-6.5s6.5 2.9 6.5 6.5',
			'M15.5 4.6a3.5 3.5 0 0 1 0 6.8',
			'M18 13.9c2.1.8 3.5 3 3.5 6.1'
		]
	},
	audit: {
		viewBox: GRID,
		paths: [
			'M7 3.5h10a2 2 0 0 1 2 2v13.5a2 2 0 0 1 -2 2h-10a2 2 0 0 1 -2 -2v-13.5a2 2 0 0 1 2 -2z',
			'M9 3.5h6v3H9z',
			'M8.5 11h7M8.5 14.5h7M8.5 18h4'
		]
	},
	thief: {
		viewBox: GRID,
		paths: [
			'M8.25 8a3.75 3.75 0 1 0 7.5 0a3.75 3.75 0 1 0 -7.5 0',
			'M7.75 7.5h8.5',
			'M4.75 20.25c0-4 3.25-6.75 7.25-6.75s7.25 2.75 7.25 6.75'
		]
	},
	/* A gate a request passes through: the reader's reverse proxy. */
	proxy: {
		viewBox: GRID,
		paths: [
			'M9.5 3.5h5a1.5 1.5 0 0 1 1.5 1.5v14a1.5 1.5 0 0 1 -1.5 1.5h-5a1.5 1.5 0 0 1 -1.5 -1.5v-14a1.5 1.5 0 0 1 1.5 -1.5z',
			'M12 8v8',
			'M2.5 12h5.5M16 12h5.5',
			'M19 9.5l2.5 2.5l-2.5 2.5'
		]
	}
};

export const GUIDE_MARKS: Readonly<Record<ProblemMark, Glyph>> = {
	password: {
		viewBox: GRID,
		paths: [
			'M5 7.5h14a2.5 2.5 0 0 1 2.5 2.5v4a2.5 2.5 0 0 1 -2.5 2.5h-14a2.5 2.5 0 0 1 -2.5 -2.5v-4a2.5 2.5 0 0 1 2.5 -2.5z',
			'M7 12a0.5 0.5 0 1 0 1 0a0.5 0.5 0 1 0 -1 0',
			'M11.5 12a0.5 0.5 0 1 0 1 0a0.5 0.5 0 1 0 -1 0',
			'M16 12a0.5 0.5 0 1 0 1 0a0.5 0.5 0 1 0 -1 0'
		]
	},
	secret: {
		viewBox: GRID,
		paths: [
			'M3.75 15.5a4.25 4.25 0 1 0 8.5 0a4.25 4.25 0 1 0 -8.5 0',
			'M11 12.5l8.5-8.5M16.25 7.25l2.5 2.5M13.75 9.75l2 2'
		]
	},
	open: {
		viewBox: GRID,
		paths: [
			'M7 11h10a2 2 0 0 1 2 2v6a2 2 0 0 1 -2 2h-10a2 2 0 0 1 -2 -2v-6a2 2 0 0 1 2 -2z',
			'M8 11V7.5a4 4 0 0 1 7.7-1.5'
		]
	},
	copy: {
		viewBox: GRID,
		paths: [
			'M10.5 8.5h8a2 2 0 0 1 2 2v8a2 2 0 0 1 -2 2h-8a2 2 0 0 1 -2 -2v-8a2 2 0 0 1 2 -2z',
			'M15.5 8.5v-3a2 2 0 0 0-2-2h-8a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h3'
		]
	},
	missing: {
		viewBox: GRID,
		paths: ['M9.1 9a3 3 0 0 1 5.8 1c0 2-3 2.5-3 4.5', 'M12 18h.01']
	}
};

/* The problem's mark turns into this once FoxAuth is in the picture. */
export const GUIDE_FIXED: Glyph = {
	viewBox: GRID,
	paths: ['M5 12.5l4.5 4.5L19 7']
};
