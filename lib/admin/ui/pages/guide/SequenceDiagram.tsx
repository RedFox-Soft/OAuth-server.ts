import {
	useEffect,
	useId,
	useMemo,
	useRef,
	useState,
	type CSSProperties
} from 'react';
import { Button, Flex, theme } from 'antd';
import { PlayCircleOutlined } from '@ant-design/icons';
import type {
	GuideLane,
	GuidePart,
	GuideStep
} from '../../../../consts/situation_guide.js';
import { GUIDE_PARTS } from '../../../../situation_guide/parts.js';

/*
 * One renderer for every guide diagram: the lanes across the top, each headed by its part (the drawing the answer's
 * pictures give that lane) and its name, the steps as numbered arrows down, in one visual
 * vocabulary (FoxAuth always the accent, a service outside the reader's control dashed, a refusal red and dashed).
 * Every colour is a custom property set from the antd token, so the diagram wears whatever theme the console has.
 *
 * Laid out from the measured width of its box and the measured width of each label, never from fixed coordinates:
 * a label wraps rather than being cut, a word too long for its room breaks at its punctuation, and where the
 * lanes cannot sit side by side (a narrow phone) each step is drawn as its own row instead. The numbered list under
 * it says the same thing in words, and pointing at or focusing a step picks out its arrow.
 *
 * Drawn only in the browser, once the box has a width; the server renders the list, which is the whole content.
 */

type Measure = (text: string, px: number, weight: number) => number;

let measureContext: CanvasRenderingContext2D | null | undefined;

function measurer(family: string): Measure {
	if (measureContext === undefined) {
		measureContext = document.createElement('canvas').getContext('2d');
	}
	const context = measureContext;
	return (text, px, weight) => {
		if (!context) return text.length * px * 0.6;
		context.font = `${String(weight)} ${String(px)}px ${family}`;
		return context.measureText(text).width;
	};
}

/* A word wider than its room breaks after its punctuation, then anywhere: a label is never wider than its room. */
function breakWord(
	word: string,
	maxW: number,
	width: (s: string) => number
): string[] {
	if (width(word) <= maxW) return [word];
	const pieces = word.split(/(?<=[./,\-@])/);
	const lines: string[] = [];
	let current = '';
	for (const piece of pieces) {
		const next = current + piece;
		if (current && width(next) > maxW) {
			lines.push(current);
			current = piece;
		} else current = next;
	}
	const out: string[] = [];
	for (const line of current ? [...lines, current] : lines) {
		if (width(line) <= maxW) {
			out.push(line);
			continue;
		}
		let part = '';
		for (const ch of line) {
			if (part && width(part + ch) > maxW) {
				out.push(part);
				part = ch;
			} else part += ch;
		}
		if (part) out.push(part);
	}
	return out;
}

interface Wrapped {
	lines: string[];
	/* A word had to be broken to fit. */
	broken: boolean;
}

/* Greedy wrap by measured width. */
function wrapLabel(
	text: string,
	maxW: number,
	px: number,
	weight: number,
	measure: Measure
): Wrapped {
	const width = (s: string) => measure(s, px, weight);
	const lines: string[] = [];
	let broken = false;
	let current = '';
	for (const word of text.split(' ')) {
		const next = current ? `${current} ${word}` : word;
		if (width(next) <= maxW) {
			current = next;
			continue;
		}
		if (current) lines.push(current);
		const parts = breakWord(word, maxW, width);
		if (parts.length > 1) broken = true;
		current = parts.pop() ?? '';
		lines.push(...parts);
	}
	if (current) lines.push(current);
	return { lines, broken };
}

function clamp(v: number, lo: number, hi: number): number {
	return lo > hi ? (lo + hi) / 2 : Math.max(lo, Math.min(hi, v));
}

type Tone = 'plain' | 'fox' | 'outside';

function toneOf(lane: GuideLane | undefined): Tone {
	if (lane?.kind === 'fox') return 'fox';
	if (lane?.kind === 'outside' || lane?.kind === 'company') return 'outside';
	return 'plain';
}

interface Text {
	x: number;
	y: number;
	anchor: 'start' | 'middle' | 'end';
	text: string;
}

interface Box {
	x: number;
	y: number;
	w: number;
	h: number;
	tone: Tone;
	texts: Text[];
	/* The lane's part (lib/situation_guide/parts.ts), drawn `size` wide from its top-left corner. */
	icon?: { part: GuidePart; x: number; y: number; size: number };
}

interface StepShape {
	from: Tone;
	refusal: boolean;
	/* How the arrow is drawn: a redirect long-dashed, a token thick. */
	kind: GuideStep['style'];
	arrow?: { x1: number; x2: number; y: number };
	cross?: { x: number; y: number };
	self?: { x: number; y: number };
	number: { x: number; y: number };
	labels: Text[];
	/* Stacked rows draw their own participants. */
	boxes: Box[];
}

interface Drawing {
	width: number;
	height: number;
	fontSize: number;
	headSize: number;
	lanes: (Box & { life: { x: number; y1: number; y2: number } })[];
	steps: StepShape[];
}

const PAD = 2;

function across(
	lanes: GuideLane[],
	steps: GuideStep[],
	W: number,
	measure: Measure
): { drawing: Drawing; fits: boolean } {
	const n = Math.max(1, lanes.length);
	const laneW = (W - 2 * PAD) / n;
	const narrow = W < 560;
	const boxW = Math.min(laneW - 6, 168);
	const headFs = narrow ? 11 : 12.5;
	const headLh = headFs + 3;
	// Each head carries its lane's part over its name, the drawing the answer's pictures use for that lane.
	const iconSize = narrow ? 16 : 18;
	const textTop = 8 + iconSize + 2;
	const heads = lanes.map((l) =>
		wrapLabel(l.label, boxW - 10, headFs, 700, measure)
	);
	const fits = laneW >= 72 && heads.every((h) => !h.broken);
	const maxHeadLines = Math.max(1, ...heads.map((h) => h.lines.length));
	const headH = textTop + maxHeadLines * headLh + 8;
	const fs = narrow ? 11 : 12.5;
	const lh = fs + 3;
	const cx = (i: number) => PAD + laneW * (i + 0.5);
	const index = new Map(lanes.map((l, i) => [l.id, i]));
	const byId = new Map(lanes.map((l) => [l.id, l]));
	const widest = (lines: string[]) =>
		Math.max(0, ...lines.map((ln) => measure(ln, fs, 600)));

	const shapes: StepShape[] = [];
	let y = headH + 14;
	for (const s of steps) {
		const fi = index.get(s.from) ?? 0;
		const ti = index.get(s.to) ?? 0;
		const from = toneOf(byId.get(s.from));
		const refusal = s.style === 'refusal';
		if (fi === ti) {
			const x = cx(fi);
			const right = W - PAD - (x + 16);
			const left = x - 16 - PAD;
			const dir = right >= left ? 1 : -1;
			const room = Math.max(right, left);
			if (room >= 64) {
				const { lines } = wrapLabel(s.label, room, fs, 600, measure);
				const h = Math.max(24, lines.length * lh + 4);
				const cy = y + h / 2;
				const ty = cy - ((lines.length - 1) * lh) / 2 + fs * 0.35;
				shapes.push({
					from,
					refusal,
					kind: s.style,
					self: { x, y: cy },
					number: { x, y: cy },
					labels: lines.map((text, k) => ({
						x: x + dir * 16,
						y: ty + k * lh,
						anchor: dir > 0 ? 'start' : 'end',
						text
					})),
					boxes: []
				});
				y += h + 12;
			} else {
				const maxW = Math.min(laneW * 1.8, W - 2 * PAD - 4);
				const { lines } = wrapLabel(s.label, maxW, fs, 600, measure);
				const tw = widest(lines);
				const tx = clamp(x, PAD + tw / 2 + 2, W - PAD - tw / 2 - 2);
				const cy = y + 10;
				shapes.push({
					from,
					refusal,
					kind: s.style,
					number: { x, y: cy },
					labels: lines.map((text, k) => ({
						x: tx,
						y: cy + 14 + (k + 1) * lh - 3,
						anchor: 'middle',
						text
					})),
					boxes: []
				});
				y += 24 + lines.length * lh + 12;
			}
			continue;
		}
		const x1 = cx(fi);
		const x2 = cx(ti);
		const d = x2 > x1 ? 1 : -1;
		const span = Math.abs(x2 - x1);
		const maxW = Math.min(
			Math.max(span - 18, narrow ? laneW * 1.7 : 150),
			W - 2 * PAD - 4
		);
		const { lines } = wrapLabel(s.label, maxW, fs, 600, measure);
		const tw = widest(lines);
		const tx = clamp(
			(x1 + x2) / 2 + d * 6,
			PAD + tw / 2 + 2,
			W - PAD - tw / 2 - 2
		);
		const ay = y + lines.length * lh + 8;
		shapes.push({
			from,
			refusal,
			kind: s.style,
			arrow: { x1: x1 + d * 12, x2: x2 - d * 3, y: ay },
			...(refusal ? { cross: { x: x2 - d * 22, y: ay } } : {}),
			number: { x: x1, y: ay },
			labels: lines.map((text, k) => ({
				x: tx,
				y: y + (k + 1) * lh - 3,
				anchor: 'middle',
				text
			})),
			boxes: []
		});
		y = ay + 22;
	}
	const H = y + 4;
	return {
		fits,
		drawing: {
			width: W,
			height: H,
			fontSize: fs,
			headSize: headFs,
			lanes: lanes.map((l, i) => {
				const x = cx(i);
				return {
					x: x - boxW / 2,
					y: 2,
					w: boxW,
					h: headH - 6,
					tone: toneOf(l),
					texts: (heads[i]?.lines ?? []).map((text, k) => ({
						x,
						y: textTop + (k + 1) * headLh - 3,
						anchor: 'middle' as const,
						text
					})),
					icon: {
						part: l.part,
						x: x - iconSize / 2,
						y: 7,
						size: iconSize
					},
					life: { x, y1: headH - 4, y2: H - 2 }
				};
			}),
			steps: shapes
		}
	};
}

/*
 * Where the lanes cannot sit side by side, each step becomes a row of its own: who acts, an arrow, and to whom,
 * with what happens written under it across the whole width.
 */
function stacked(
	lanes: GuideLane[],
	steps: GuideStep[],
	W: number,
	measure: Measure
): Drawing {
	const fs = 11;
	const lh = fs + 3;
	const headFs = 11;
	const headLh = headFs + 3;
	const gap = Math.max(52, Math.round(W * 0.2));
	const chipW = (W - 2 * PAD - gap) / 2;
	const byId = new Map(lanes.map((l) => [l.id, l]));
	const chip = (laneId: string, x: number, y: number): Box => {
		const lane = byId.get(laneId);
		// The lane's part stands at the chip's left, and its name is centred in the rest.
		const icon = 14;
		const inset = 6 + icon;
		const { lines } = wrapLabel(
			lane?.label ?? laneId,
			chipW - 12 - inset,
			headFs,
			700,
			measure
		);
		const h = Math.max(icon + 10, lines.length * headLh + 10);
		return {
			x,
			y,
			w: chipW,
			h,
			tone: toneOf(lane),
			texts: lines.map((text, k) => ({
				x: x + inset + (chipW - inset) / 2,
				y: y + (h - lines.length * headLh) / 2 + (k + 1) * headLh - 3,
				anchor: 'middle',
				text
			})),
			...(lane
				? {
						icon: {
							part: lane.part,
							x: x + 6,
							y: y + (h - icon) / 2,
							size: icon
						}
					}
				: {})
		};
	};
	const shapes: StepShape[] = [];
	let y = 4;
	for (const s of steps) {
		const from = toneOf(byId.get(s.from));
		const refusal = s.style === 'refusal';
		const left = chip(s.from, PAD, y);
		const self = s.from === s.to;
		const right = self ? null : chip(s.to, W - PAD - chipW, y);
		const rowH = Math.max(left.h, right?.h ?? 0);
		left.y = y + (rowH - left.h) / 2;
		left.texts = left.texts.map((t) => ({
			...t,
			y: t.y + (rowH - left.h) / 2
		}));
		if (left.icon) {
			left.icon = { ...left.icon, y: left.icon.y + (rowH - left.h) / 2 };
		}
		if (right) {
			const shift = (rowH - right.h) / 2;
			right.y = y + shift;
			right.texts = right.texts.map((t) => ({ ...t, y: t.y + shift }));
			if (right.icon) right.icon = { ...right.icon, y: right.icon.y + shift };
		}
		const my = y + rowH / 2;
		const ax1 = PAD + chipW;
		const ax2 = W - PAD - chipW;
		const { lines } = wrapLabel(s.label, W - 2 * PAD - 8, fs, 600, measure);
		const ly = y + rowH + 6;
		shapes.push({
			from,
			refusal,
			kind: s.style,
			...(right
				? {
						arrow: { x1: ax1 + 4, x2: ax2 - 3, y: my },
						...(refusal ? { cross: { x: ax2 - 18, y: my } } : {})
					}
				: { self: { x: ax1 + gap / 2, y: my } }),
			number: { x: ax1 + gap / 2, y: my },
			labels: lines.map((text, k) => ({
				x: W / 2,
				y: ly + (k + 1) * lh - 3,
				anchor: 'middle',
				text
			})),
			boxes: right ? [left, right] : [left]
		});
		y = ly + lines.length * lh + 16;
	}
	return {
		width: W,
		height: y,
		fontSize: fs,
		headSize: headFs,
		lanes: [],
		steps: shapes
	};
}

/* The diagram for a box `W` wide: side by side when the lanes fit, a row per step below 480 px when they do not. */
export function drawSequence(
	lanes: GuideLane[],
	steps: GuideStep[],
	W: number,
	measure: Measure
): Drawing {
	const side = across(lanes, steps, W, measure);
	if (W < 480 && !side.fits) return stacked(lanes, steps, W, measure);
	return side.drawing;
}

const CSS = `
.guide-dia { width: 100%; }
.guide-dia svg { display: block; width: 100%; height: auto; overflow: visible; font-family: inherit; }
.guide-dia .box { fill: var(--gd-surface); stroke: var(--gd-line); stroke-width: 1.2; }
.guide-dia .box.fox { fill: var(--gd-accent-soft); stroke: var(--gd-accent); stroke-width: 1.6; }
.guide-dia .box.outside { stroke: var(--gd-life); stroke-dasharray: 4 3; }
.guide-dia .box-t { fill: var(--gd-fg); font-weight: 700; }
.guide-dia .box-i { fill: none; stroke: var(--gd-fg); stroke-linecap: round; stroke-linejoin: round; }
.guide-dia .box-i.fox { stroke: var(--gd-accent); }
.guide-dia .life { stroke: var(--gd-life); stroke-width: 1.2; stroke-dasharray: 3 5; }
.guide-dia .life.fox { stroke: var(--gd-accent); opacity: 0.55; }
.guide-dia .arr { stroke: var(--gd-arrow); stroke-width: 1.8; fill: none; }
.guide-dia .st.fox .arr { stroke: var(--gd-accent); }
.guide-dia .st.refusal .arr { stroke: var(--gd-deny); stroke-dasharray: 5 4; }
.guide-dia .mk { fill: var(--gd-arrow); }
.guide-dia .mk.fox { fill: var(--gd-accent); }
.guide-dia .mk.refusal { fill: var(--gd-deny); }
.guide-dia .num-c { fill: var(--gd-ink); }
.guide-dia .st.fox .num-c { fill: var(--gd-accent); }
.guide-dia .st.refusal .num-c { fill: var(--gd-deny); }
.guide-dia .num-t { fill: var(--gd-on-ink); font-size: 11px; font-weight: 800; }
.guide-dia .st.fox .num-t, .guide-dia .st.refusal .num-t { fill: var(--gd-on-accent); }
.guide-dia .lbl { fill: var(--gd-fg); font-weight: 600; paint-order: stroke; stroke: var(--gd-card); stroke-width: 5px; stroke-linejoin: round; }
.guide-dia .st.refusal .lbl { fill: var(--gd-deny); }
.guide-dia .self-dot { fill: var(--gd-surface); stroke: var(--gd-arrow); stroke-width: 1.6; }
.guide-dia .st.fox .self-dot { stroke: var(--gd-accent); }
.guide-dia .x-mark { stroke: var(--gd-deny); stroke-width: 2.4; stroke-linecap: round; }
.guide-dia .st { transition: opacity 0.15s; }
.guide-dia.anim .st { opacity: 0; animation: gd-step-in 0.45s ease forwards; animation-delay: calc(var(--d) * 280ms + 120ms); }
@keyframes gd-step-in { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: none; } }
.guide-dia.picking .st, .guide-dia.picking.anim .st { opacity: 0.2; animation: none; }
.guide-dia.picking .st.on, .guide-dia.picking.anim .st.on { opacity: 1; animation: none; }
.guide-dia .st.redirect .arr { stroke-dasharray: 8 4; }
.guide-dia .st.token .arr { stroke-width: 2.8; }
.guide-dia .st.on .arr { stroke-width: 3.4; }
.guide-steps { list-style: none; margin: 12px 0 0; padding: 0; display: grid; gap: 2px; }
.guide-steps li { display: grid; grid-template-columns: 24px minmax(0, 1fr); gap: 12px; padding: 6px 8px; border-radius: 6px; cursor: default; }
.guide-steps li:hover, .guide-steps li.on { background: var(--gd-surface-2); }
.guide-steps li:focus { outline: none; }
.guide-steps li:focus-visible { outline: 2px solid var(--gd-accent); outline-offset: 1px; }
.guide-steps .sn { display: grid; place-items: center; width: 24px; height: 24px; border-radius: 999px; background: var(--gd-ink); color: var(--gd-on-ink); font-size: 12px; font-weight: 800; }
.guide-steps li.fox .sn { background: var(--gd-accent); color: var(--gd-on-accent); }
.guide-steps li.refusal .sn { background: var(--gd-deny); color: var(--gd-on-accent); }
.guide-steps .who { display: block; font-size: 12px; font-weight: 600; color: var(--gd-muted); }
.guide-steps .what { display: block; color: var(--gd-fg); }
@media (prefers-reduced-motion: reduce) {
  .guide-dia .st { transition: none; }
  .guide-dia.anim .st { animation: none; opacity: 1; }
  .guide-dia.picking.anim .st { opacity: 0.2; }
  .guide-dia.picking.anim .st.on { opacity: 1; }
}
.guide-scope .ant-typography.ant-typography-secondary { color: var(--gd-muted); }
`;

/* The diagram's palette, from the antd token: also read by the legend's keys, so they match the drawing. */
export function useDiagramPalette(): CSSProperties {
	const { token } = theme.useToken();
	return {
		'--gd-fg': token.colorText,
		'--gd-muted': token.colorTextSecondary,
		'--gd-line': token.colorBorder,
		'--gd-life': token.colorTextTertiary,
		'--gd-arrow': token.colorTextSecondary,
		'--gd-card': token.colorBgContainer,
		'--gd-surface': token.colorBgContainer,
		'--gd-surface-2': token.colorFillTertiary,
		'--gd-accent': token.colorPrimary,
		'--gd-accent-soft': token.colorPrimaryBg,
		'--gd-on-accent': token.colorTextLightSolid,
		'--gd-ink': token.colorText,
		'--gd-on-ink': token.colorBgContainer,
		'--gd-deny': token.colorErrorActive,
		// The pictures' own (Scene.tsx): the frames, FoxAuth's ring, the fixed part and the example app's logo.
		'--gd-line-2': token.colorBorderSecondary,
		'--gd-accent-border': token.colorPrimaryBorder,
		'--gd-accent-ring': token.colorPrimaryBgHover,
		'--gd-ready-ink': token.colorPrimaryTextActive,
		// antd's error text (#ff4d4f) is 3.0:1 on the frames' layout grey; red-7 is 5.1:1, so a refusal stays readable.
		'--gd-deny-ink': token.red7,
		'--gd-good': token.colorSuccessActive,
		'--gd-problem-bg': token.colorBgLayout,
		'--gd-shadow': token.boxShadowTertiary,
		'--gd-mono': token.fontFamilyCode,
		'--gd-app': token.cyan8
	} as CSSProperties;
}

/*
 * The stylesheet the diagram, the legend and the guide's text draw with. Every diagram renders it, so an answer shown
 * on its own (the Overview) is drawn as on the guide page; a second copy on the same page is harmless. Under
 * `.guide-scope` it also keeps the guide's own secondary text, links and primary buttons at 4.5:1 or better, without
 * touching the console's theme.
 */
export function DiagramStyles() {
	return <style dangerouslySetInnerHTML={{ __html: CSS }} />;
}

function laneLabel(lanes: GuideLane[], id: string): string {
	return lanes.find((l) => l.id === id)?.label ?? id;
}

function stepClass(lanes: GuideLane[], s: GuideStep): string {
	if (s.style === 'refusal') return 'refusal';
	return lanes.find((l) => l.id === s.from)?.kind === 'fox' ? 'fox' : '';
}

export function SequenceDiagram({
	lanes,
	steps,
	title
}: {
	lanes: GuideLane[];
	steps: GuideStep[];
	title: string;
}) {
	const palette = useDiagramPalette();
	const box = useRef<HTMLDivElement>(null);
	const [frame, setFrame] = useState<{ width: number; family: string } | null>(
		null
	);
	const [active, setActive] = useState<number | null>(null);
	// Bumped by "Show steps": a new key remounts the drawing, which plays the steps in again.
	const [replay, setReplay] = useState(0);
	// A marker is referenced by id, and `useId`'s own characters are not all safe inside `url(#…)`.
	const uid = `gd${useId().replace(/[^a-zA-Z0-9_-]/g, '')}`;

	useEffect(() => {
		const el = box.current;
		if (!el) return;
		const read = () => {
			const width = Math.max(240, Math.floor(el.clientWidth));
			const family = getComputedStyle(el).fontFamily || 'sans-serif';
			setFrame((f) =>
				f && f.width === width && f.family === family ? f : { width, family }
			);
		};
		const observer = new ResizeObserver(read);
		observer.observe(el);
		return () => {
			observer.disconnect();
		};
	}, []);

	const drawing = useMemo(
		() =>
			frame
				? drawSequence(lanes, steps, frame.width, measurer(frame.family))
				: null,
		[frame, lanes, steps]
	);

	return (
		<div style={palette}>
			<DiagramStyles />
			<Flex justify="flex-end">
				<Button
					size="small"
					icon={<PlayCircleOutlined />}
					onClick={() => {
						setReplay((n) => n + 1);
					}}
				>
					Show steps
				</Button>
			</Flex>
			<div
				ref={box}
				className={`guide-dia anim${active === null ? '' : ' picking'}`}
			>
				{drawing && (
					<svg
						key={replay}
						viewBox={`0 0 ${String(drawing.width)} ${String(drawing.height)}`}
						width={drawing.width}
						height={drawing.height}
						role="img"
						aria-labelledby={`${uid}t`}
					>
						<title
							id={`${uid}t`}
						>{`Diagram: ${title}. The numbered steps below say the same in words.`}</title>
						<defs>
							{(['', 'fox', 'refusal'] as const).map((tone) => (
								<marker
									key={tone || 'plain'}
									id={`${uid}m${tone}`}
									viewBox="0 0 10 10"
									refX="9"
									refY="5"
									markerWidth="8"
									markerHeight="8"
									orient="auto-start-reverse"
								>
									<path
										className={`mk ${tone}`}
										d="M0 0L10 5L0 10z"
									/>
								</marker>
							))}
						</defs>
						{drawing.lanes.map((lane, i) => (
							<g key={`lane${String(i)}`}>
								<line
									className={`life${lane.tone === 'fox' ? ' fox' : ''}`}
									x1={lane.life.x}
									y1={lane.life.y1}
									x2={lane.life.x}
									y2={lane.life.y2}
								/>
								<BoxShape
									box={lane}
									size={drawing.headSize}
								/>
							</g>
						))}
						{drawing.steps.map((s, i) => {
							const tone = s.refusal
								? 'refusal'
								: s.from === 'fox'
									? 'fox'
									: '';
							return (
								<g
									key={`step${String(i)}`}
									className={`st ${tone} ${s.kind ?? ''}${active === i ? ' on' : ''}`}
									style={{ '--d': i } as CSSProperties}
								>
									{s.boxes.map((b, k) => (
										<BoxShape
											key={`b${String(k)}`}
											box={b}
											size={drawing.headSize}
										/>
									))}
									{s.arrow && (
										<line
											className="arr"
											x1={s.arrow.x1}
											y1={s.arrow.y}
											x2={s.arrow.x2}
											y2={s.arrow.y}
											markerEnd={`url(#${uid}m${tone})`}
										/>
									)}
									{s.cross && (
										<path
											className="x-mark"
											d={`M${String(s.cross.x - 5)} ${String(s.cross.y - 5)}l10 10M${String(s.cross.x + 5)} ${String(s.cross.y - 5)}l-10 10`}
										/>
									)}
									{s.self && (
										<rect
											className="self-dot"
											x={s.self.x - 6}
											y={s.self.y - 10}
											width="12"
											height="20"
											rx="4"
										/>
									)}
									<circle
										className="num-c"
										cx={s.number.x}
										cy={s.number.y}
										r="10"
									/>
									<text
										className="num-t"
										x={s.number.x}
										y={s.number.y + 4}
										textAnchor="middle"
									>
										{i + 1}
									</text>
									{s.labels.map((t, k) => (
										<text
											key={`l${String(k)}`}
											className="lbl"
											style={{ fontSize: drawing.fontSize }}
											x={t.x}
											y={t.y}
											textAnchor={t.anchor}
										>
											{t.text}
										</text>
									))}
								</g>
							);
						})}
					</svg>
				)}
			</div>
			<ol
				className="guide-steps"
				aria-label={`Steps: ${title}`}
				onMouseLeave={() => {
					setActive(null);
				}}
			>
				{steps.map((s, i) => (
					<li
						key={`${s.from}-${s.to}-${String(i)}`}
						tabIndex={0}
						className={`${stepClass(lanes, s)}${active === i ? ' on' : ''}`}
						onMouseEnter={() => {
							setActive(i);
						}}
						onFocus={() => {
							setActive(i);
						}}
						onBlur={() => {
							setActive(null);
						}}
					>
						<span
							className="sn"
							aria-hidden="true"
						>
							{i + 1}
						</span>
						<span>
							<span className="who">
								{s.from === s.to
									? laneLabel(lanes, s.from)
									: `${laneLabel(lanes, s.from)} to ${laneLabel(lanes, s.to)}`}
							</span>
							<span className="what">{s.text}</span>
						</span>
					</li>
				))}
			</ol>
		</div>
	);
}

function BoxShape({ box, size }: { box: Box; size: number }) {
	return (
		<>
			<rect
				className={`box ${box.tone}`}
				x={box.x}
				y={box.y}
				width={box.w}
				height={box.h}
				rx="8"
			/>
			{box.icon && (
				<g
					className={`box-i ${box.tone}`}
					transform={`translate(${String(box.icon.x)} ${String(box.icon.y)}) scale(${String(box.icon.size / 24)})`}
					strokeWidth={1.75}
				>
					{GUIDE_PARTS[box.icon.part].paths.map((d) => (
						<path
							key={d}
							d={d}
						/>
					))}
				</g>
			)}
			{box.texts.map((t, k) => (
				<text
					key={`t${String(k)}`}
					className="box-t"
					style={{ fontSize: size }}
					x={t.x}
					y={t.y}
					textAnchor={t.anchor}
				>
					{t.text}
				</text>
			))}
		</>
	);
}
