import type { CSSProperties, ReactNode } from 'react';
import type { GuideSituation } from '../../../../consts/situation_guide.js';
import { sceneOf, type Scene } from '../../../../situation_guide/scene.js';
import { Glyph } from './Part.js';

/*
 * One picture of an answer, "Your problem" or "With FoxAuth", drawn from the scene lib/situation_guide/scene.ts works
 * out, layout included: which nodes stand on the row and which above it, and which links arc at what level. The
 * site's renderer (website/src/components/guide/Scene.astro) reads the same fields through the docs export; this one
 * turns them into the same sizes, so the console and the site draw one picture. The two copies of the sizing are kept
 * in step by hand (the site reads lib only through the export, so it cannot import a helper): change both together.
 *
 * - the row's nodes are columns of one grid, each a part in a tile with its label under it in HTML;
 * - a node above the row (FoxAuth beside the path) stands over the middle of the row nodes it links to, its label
 *   beside its tile;
 * - a straight link runs centre to centre, under the tiles; an arc leaves the top of one tile and lands on the top of
 *   the other, high enough to clear the tiles and their marks between.
 *
 * The lines are an SVG stretched to the width (x in thousandths, y in pixels, strokes unscaled), so the picture
 * follows its frame without measuring it. The mark sits on the part with the problem; in the solution the same part
 * carries the check. The whole picture is decoration: its frame's caption says the same in words.
 */

const TILE = 40;
/* How far an arc clears the tile tops at its middle: over the marks (8 px proud) at level 1, a step more per level. */
const clearance = (level: number) => 16 + (level - 1) * 12;
/* A cubic with both handles at one height peaks at three quarters of it. */
const handle = (level: number) => clearance(level) / 0.75;
const pct = (x: number) => `${(x * 100).toFixed(3)}%`;

function Words({ text }: { text: string }) {
	const words = text.split(' ').filter((word) => word.length > 0);
	return (
		<>
			{words.map((word, i) => (
				<span key={`${word}${String(i)}`}>
					{i > 0 && ' '}
					<span className="gs-word">{word}</span>
				</span>
			))}
		</>
	);
}

export function ScenePicture({
	scene,
	labels
}: {
	scene: Scene;
	labels: ReadonlyMap<string, string>;
}) {
	/* The solution's check, where lib/situation_guide/scene.ts puts it (never on a party the fix refuses). */
	const fixedAt = scene.fixed;
	const byLane = new Map(scene.nodes.map((node) => [node.lane, node]));
	const row = scene.row.flatMap((lane) => byLane.get(lane) ?? []);
	const above = scene.above.flatMap((lane) => byLane.get(lane) ?? []);
	const n = Math.max(1, row.length);
	const indexOf = new Map(row.map((node, i) => [node.lane, i]));
	const columnX = (i: number) => (i + 0.5) / n;
	const levels = Math.max(0, ...scene.links.map((l) => l.arc ?? 0));

	const rowTop =
		above.length > 0
			? TILE + Math.max(30, levels > 0 ? clearance(levels) + 14 : 0)
			: levels > 0
				? clearance(levels) + 4
				: 0;
	const rowY = rowTop + TILE / 2;
	const aboveY = TILE / 2;
	const height = rowY + 2;

	const aboveX = new Map(
		above.map((node) => {
			const xs = scene.links
				.flatMap((l) =>
					l.from === node.lane ? [l.to] : l.to === node.lane ? [l.from] : []
				)
				.filter((lane) => indexOf.has(lane))
				.map((lane) => columnX(indexOf.get(lane) ?? 0));
			const x = xs.length > 0 ? xs.reduce((a, b) => a + b, 0) / xs.length : 0.5;
			return [node.lane, x];
		})
	);

	const pointOf = (lane: string): { x: number; y: number } | undefined => {
		const i = indexOf.get(lane);
		if (i !== undefined) return { x: columnX(i), y: rowY };
		const x = aboveX.get(lane);
		return x === undefined ? undefined : { x, y: aboveY };
	};

	const drawn = scene.links.flatMap((l) => {
		const a = pointOf(l.from);
		const b = pointOf(l.to);
		if (!a || !b) return [];
		if (l.arc !== undefined) {
			const up = rowTop - handle(l.arc);
			return [
				{
					kind: l.kind,
					d: `M${String(a.x * 1000)} ${String(rowTop)}C${String(a.x * 1000)} ${String(up)} ${String(b.x * 1000)} ${String(up)} ${String(b.x * 1000)} ${String(rowTop)}`,
					mid: { x: (a.x + b.x) / 2, y: rowTop - clearance(l.arc) }
				}
			];
		}
		return [
			{
				kind: l.kind,
				d: `M${String(a.x * 1000)} ${String(a.y)}L${String(b.x * 1000)} ${String(b.y)}`,
				mid: { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 }
			}
		];
	});

	const mark = scene.mark;
	const label = (lane: string) => labels.get(lane) ?? lane;

	return (
		<div
			className={`gs-scene${above.length > 0 ? ' beside' : ''}`}
			style={{ '--n': n, '--row-top': `${String(rowTop)}px` } as CSSProperties}
			aria-hidden="true"
		>
			<svg
				className="gs-scene-links"
				viewBox={`0 0 1000 ${String(height)}`}
				preserveAspectRatio="none"
				style={{ height }}
			>
				{drawn.map((line, i) => (
					<path
						key={`${line.d}${String(i)}`}
						d={line.d}
						className={`gs-link ${line.kind}`}
						vectorEffect="non-scaling-stroke"
					/>
				))}
			</svg>
			{drawn
				.filter((line) => line.kind !== 'direct')
				.map((line, i) => (
					<span
						key={`m${String(i)}`}
						className={line.kind === 'token' ? 'gs-link-chip' : 'gs-link-cut'}
						style={{ left: pct(line.mid.x), top: line.mid.y }}
					>
						{line.kind === 'broken' && '×'}
					</span>
				))}
			{above.map((node) => {
				const x = aboveX.get(node.lane) ?? 0.5;
				return (
					<span
						key={node.lane}
						className={`gs-node ${node.role} above${x > 0.6 ? ' start' : ''}`}
						style={{ left: pct(x) }}
					>
						<span className="gs-tile">
							<Glyph part={node.part} />
						</span>
						<span className="gs-node-label">
							<Words text={label(node.lane)} />
						</span>
					</span>
				);
			})}
			<div className="gs-scene-row">
				{row.map((node) => (
					<span
						key={node.lane}
						className={`gs-node ${node.role}${mark?.at === node.lane ? ' bad' : ''}${fixedAt === node.lane ? ' good' : ''}`}
					>
						<span className="gs-tile">
							<Glyph part={node.part} />
							{mark?.at === node.lane && (
								<span className="gs-badge bad">
									<Glyph
										mark={mark.kind}
										strokeWidth={2.5}
									/>
								</span>
							)}
							{fixedAt === node.lane && (
								<span className="gs-badge good">
									<Glyph strokeWidth={3} />
								</span>
							)}
						</span>
						<span className="gs-node-label">
							<Words text={label(node.lane)} />
						</span>
					</span>
				))}
			</div>
		</div>
	);
}

/*
 * The top of every answer: "Your problem" (the parts without FoxAuth, a red mark on the one with the problem), "With
 * FoxAuth" (the same parts, FoxAuth where it really stands, a check on the part it fixed) and "What you get" (the
 * screen the person meets, `get`). Three across where the answer panel has room (720 px), the two pictures side by
 * side with what you get under them below that, and one under the other in a phone's width: container queries on the
 * strip's own width, so the Overview's card and the guide page agree.
 */
export function Strip({
	situation: s,
	get
}: {
	situation: GuideSituation;
	get: ReactNode;
}) {
	const { problem, solution } = sceneOf(s);
	const labels = new Map(s.lanes.map((lane) => [lane.id, lane.label]));
	/* The frames share the width by how many parts each draws, so a four-part picture is not squeezed beside a two. */
	const weight = (scene: Scene) => Math.max(2, scene.row.length);
	return (
		<div className="gs-strip-wrap">
			<div
				className="gs-strip"
				role="group"
				aria-label="The problem, the fix and what you get"
				style={
					{
						'--gs-w1': `${String(weight(problem))}fr`,
						'--gs-w2': `${String(weight(solution))}fr`
					} as CSSProperties
				}
			>
				<figure className="gs-frame problem">
					<div className="gs-frame-h">
						<span
							className="gs-frame-n"
							aria-hidden="true"
						>
							1
						</span>
						Your problem
					</div>
					<div className="gs-frame-pic">
						<ScenePicture
							scene={problem}
							labels={labels}
						/>
					</div>
					<figcaption className="gs-frame-cap">{s.problem.caption}</figcaption>
				</figure>
				<span
					className="gs-turn t1"
					aria-hidden="true"
				>
					→
				</span>
				<figure className="gs-frame fix">
					<div className="gs-frame-h">
						<span
							className="gs-frame-n"
							aria-hidden="true"
						>
							2
						</span>
						With FoxAuth
					</div>
					<div className="gs-frame-pic">
						<ScenePicture
							scene={solution}
							labels={labels}
						/>
					</div>
					<figcaption className="gs-frame-cap">{s.fixCaption}</figcaption>
				</figure>
				<span
					className="gs-turn t2"
					aria-hidden="true"
				>
					→
				</span>
				<div className="gs-frame get">
					<div className="gs-frame-h">
						<span
							className="gs-frame-n"
							aria-hidden="true"
						>
							3
						</span>
						What you get
					</div>
					{get}
				</div>
			</div>
		</div>
	);
}

/*
 * The stylesheet of the guide's pictures: the parts, the option thumbnails and status marks, the scenes, the strip
 * and the mini screens. Every colour is a custom property `useDiagramPalette` sets from the antd token.
 */
const CSS = `
.gs-glyph { display: block; flex: none; }
.gs-word { display: inline-block; max-width: 100%; overflow-wrap: break-word; }

.gs-thumb { display: inline-flex; flex: none; align-items: center; height: 28px; padding: 0 6px; border-radius: 6px; background: var(--gd-surface-2); color: var(--gd-fg); }
.gs-thumb-part { display: inline-flex; align-items: center; }
.gs-thumb .gs-glyph { width: 18px; height: 18px; }
.gs-thumb-link { display: block; width: 6px; height: 1.5px; margin: 0 3px; border-radius: 2px; background: var(--gd-arrow); }
.gs-thumb.sm { height: 24px; padding: 0 5px; }
.gs-thumb.sm .gs-glyph { width: 15px; height: 15px; }
.ant-radio-wrapper-checked .gs-thumb { background: var(--gd-surface); color: var(--gd-accent); }

.gs-actor { position: relative; display: grid; flex: none; place-items: center; width: 44px; height: 38px; color: var(--gd-fg); }
.gs-actor > .gs-glyph { width: 32px; height: 32px; }
.gs-actor-at { position: absolute; right: -2px; bottom: -4px; display: grid; place-items: center; width: 22px; height: 22px; border: 1.5px solid var(--gd-line); border-radius: 6px; background: var(--gd-surface); }
.gs-actor-at .gs-glyph { width: 14px; height: 14px; }
.ant-radio-wrapper-checked .gs-actor-at { border-color: var(--gd-accent); color: var(--gd-accent); }

.gs-status { display: inline-flex; align-items: center; gap: 5px; min-width: 0; border-radius: 999px; font-weight: 500; line-height: 1.2; color: var(--gd-muted); }
.gs-status .gs-glyph { width: 14px; height: 14px; }
.gs-status.sm { font-size: 12px; }
.gs-status.md { padding: 2px 10px 2px 6px; font-size: 12px; background: var(--gd-surface-2); }
.gs-status.ready { color: var(--gd-ready-ink); }
.gs-status.md.ready { background: var(--gd-accent-soft); }
.gs-status-dot { display: grid; flex: none; place-items: center; width: 14px; height: 14px; border-radius: 999px; background: var(--gd-accent); color: var(--gd-on-accent); }
.gs-status-dot .gs-glyph { width: 10px; height: 10px; }

.gs-scene { container-type: inline-size; position: relative; width: 100%; max-width: calc(var(--n) * 104px); margin-inline: auto; }
.gs-scene-links { position: absolute; inset: 0 0 auto 0; width: 100%; overflow: visible; pointer-events: none; }
.gs-link { fill: none; stroke: var(--gd-arrow); stroke-width: 2; stroke-linecap: round; }
.gs-link.token { stroke: var(--gd-accent); stroke-width: 4; }
.gs-link.broken { stroke: var(--gd-deny); stroke-dasharray: 5 5; }
.gs-link-chip, .gs-link-cut { position: absolute; z-index: 2; transform: translate(-50%, -50%); }
.gs-link-chip { width: 22px; height: 12px; border-radius: 999px; background: var(--gd-accent); box-shadow: 0 0 0 2px var(--gs-frame-bg); }
.gs-link-chip::after { content: ''; position: absolute; inset: 3px 6px; border-radius: 999px; background: var(--gs-frame-bg); opacity: 0.85; }
.gs-link-cut { display: grid; place-items: center; width: 18px; height: 18px; border: 2px solid var(--gd-deny); border-radius: 999px; background: var(--gs-frame-bg); color: var(--gd-deny); font-size: 14px; font-weight: 700; line-height: 1; }
.gs-scene-row { position: relative; z-index: 1; display: grid; grid-template-columns: repeat(var(--n), minmax(0, 1fr)); column-gap: 4px; padding-top: var(--row-top); }
.gs-node { display: flex; min-width: 0; flex-direction: column; align-items: center; gap: 5px; text-align: center; }
.gs-node.above { position: absolute; z-index: 1; top: 0; display: block; transform: translateX(-50%); }
.gs-node.above > .gs-node-label { position: absolute; top: 50%; left: calc(100% + 12px); max-width: none; transform: translateY(-50%); white-space: nowrap; }
.gs-node.above.start > .gs-node-label { right: calc(100% + 12px); left: auto; }
.gs-tile { position: relative; display: grid; place-items: center; width: 40px; height: 40px; border: 1.5px solid var(--gd-line); border-radius: 10px; background: var(--gd-surface); color: var(--gd-fg); }
.gs-tile > .gs-glyph { width: 24px; height: 24px; }
.gs-node.fox .gs-tile { border: 2px solid var(--gd-accent); background: var(--gd-accent-soft); color: var(--gd-accent); box-shadow: 0 0 0 4px var(--gd-accent-ring); }
.gs-node.outside .gs-tile { border-style: dashed; border-color: var(--gd-life); }
.gs-node.bad .gs-tile { border-color: var(--gd-deny); }
.gs-node.good .gs-tile { border-color: var(--gd-good); }
.gs-badge { position: absolute; top: -8px; right: -10px; display: grid; place-items: center; width: 22px; height: 22px; border-radius: 999px; box-shadow: 0 0 0 2px var(--gs-frame-bg); color: var(--gd-on-accent); }
.gs-badge .gs-glyph { width: 14px; height: 14px; }
.gs-badge.bad { background: var(--gd-deny); }
.gs-badge.good { background: var(--gd-good); }
.gs-node-label { max-width: 100%; font-size: clamp(11px, 100cqi / var(--n) / 6.4, 12px); line-height: 1.25; color: var(--gd-muted); overflow-wrap: break-word; }
.gs-node.fox .gs-node-label { font-weight: 600; color: var(--gd-accent); }

.gs-strip-wrap { container: gstrip / inline-size; }
.gs-strip { display: grid; grid-template-columns: minmax(0, 1fr); grid-template-areas: 'problem' 'turn1' 'fix' 'turn2' 'get'; }
.gs-frame.problem { grid-area: problem; --gs-frame-bg: var(--gd-problem-bg); }
.gs-frame.fix { grid-area: fix; --gs-frame-bg: var(--gd-accent-soft); border-color: var(--gd-accent-border); }
.gs-frame.get { grid-area: get; }
.gs-turn.t1 { grid-area: turn1; }
.gs-turn.t2 { grid-area: turn2; }
.gs-frame { --gs-frame-bg: var(--gd-surface); display: flex; min-width: 0; flex-direction: column; margin: 0; padding: 10px 12px 12px; border: 1px solid var(--gd-line-2); border-radius: 8px; background: var(--gs-frame-bg); }
.gs-frame-h { --gs-frame-accent: var(--gd-muted); display: flex; align-items: center; gap: 6px; font-size: 11px; font-weight: 700; letter-spacing: 0.05em; text-transform: uppercase; color: var(--gs-frame-accent); }
.gs-frame.problem .gs-frame-h { --gs-frame-accent: var(--gd-deny-ink); }
.gs-frame.fix .gs-frame-h { --gs-frame-accent: var(--gd-accent); }
.gs-frame-n { display: grid; flex: none; place-items: center; width: 18px; height: 12px; border-radius: 999px; background: var(--gs-frame-accent); color: var(--gd-on-accent); font-size: 10px; letter-spacing: 0; }
.gs-frame-pic { display: flex; flex: 1; align-items: center; padding: 14px 0 8px; }
.gs-frame-cap { margin-top: auto; font-size: 13px; font-weight: 500; line-height: 1.4; text-align: center; text-wrap: balance; color: var(--gd-fg); }
.gs-turn { display: grid; place-items: center; height: 18px; color: var(--gd-accent); font-size: 18px; font-weight: 700; line-height: 1; transform: rotate(90deg); }
.gs-get { display: grid; gap: 12px; align-content: start; margin-top: 10px; }
.gs-get-pic { display: flex; justify-content: center; min-width: 0; }
.gs-get-lines { display: grid; gap: 4px; margin: 0; padding-inline-start: 18px; font-size: 13px; line-height: 1.4; color: var(--gd-muted); }
.gs-get-lines li::marker { color: var(--gd-accent); }
.gs-result { display: grid; width: 100%; max-width: 320px; gap: 8px; margin: 0; padding: 12px; list-style: none; border: 1px dashed var(--gd-line); border-radius: 12px; background: var(--gd-surface); font-size: 13px; line-height: 1.4; color: var(--gd-fg); }
.gs-result li { display: grid; grid-template-columns: 18px minmax(0, 1fr); gap: 8px; align-items: start; }
.gs-result-dot { display: grid; place-items: center; width: 18px; height: 18px; margin-top: 1px; border-radius: 999px; background: var(--gd-good); color: var(--gd-on-accent); }
.gs-result-dot .gs-glyph { width: 11px; height: 11px; }
@container gstrip (min-width: 480px) {
  .gs-strip { grid-template-columns: minmax(0, var(--gs-w1)) 20px minmax(0, var(--gs-w2)); grid-template-areas: 'problem turn1 fix' 'get get get'; row-gap: 12px; }
  .gs-turn { height: auto; transform: none; }
  .gs-turn.t2 { display: none; }
  .gs-get { grid-template-columns: minmax(0, 256px) minmax(0, 1fr); align-items: center; column-gap: 20px; }
  .gs-get-pic { justify-content: flex-start; }
}
@container gstrip (min-width: 720px) {
  .gs-strip { grid-template-columns: minmax(0, var(--gs-w1)) 20px minmax(0, var(--gs-w2)) 20px minmax(0, 3fr); grid-template-areas: 'problem turn1 fix turn2 get'; }
  .gs-turn.t2 { display: grid; }
  .gs-get { grid-template-columns: minmax(0, 1fr); }
  .gs-get-pic { justify-content: center; }
}

.gs-ms { width: 100%; max-width: 256px; overflow: hidden; border: 1px solid var(--gd-line); border-radius: 12px; background: var(--gd-surface); box-shadow: var(--gd-shadow); }
.gs-ms-bar { display: flex; align-items: center; gap: 8px; padding: 6px 10px; border-bottom: 1px solid var(--gd-line-2); font-family: var(--gd-mono); font-size: 10px; color: var(--gd-muted); }
.gs-ms-dots { display: flex; gap: 3px; }
.gs-ms-dots i { width: 6px; height: 6px; border-radius: 999px; background: var(--gd-line); }
.gs-ms-host { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.gs-ms-in { display: grid; gap: 6px; padding: 12px 14px 14px; }
.gs-ms-brand { display: flex; align-items: center; gap: 6px; font-size: 12px; font-weight: 600; color: var(--gd-muted); }
.gs-ms-logo { display: grid; place-items: center; width: 20px; height: 20px; border-radius: 5px; background: var(--gd-app); color: var(--gd-on-accent); font-size: 11px; font-weight: 700; }
.gs-ms-logo.fox { background: var(--gd-accent-soft); color: var(--gd-accent); box-shadow: inset 0 0 0 1.5px var(--gd-accent); }
.gs-ms-logo.fox .gs-glyph { width: 14px; height: 14px; }
.gs-ms-h { font-size: 14px; font-weight: 600; line-height: 1.25; color: var(--gd-fg); }
.gs-ms-t { display: block; font-size: 12px; line-height: 1.35; color: var(--gd-muted); }
.gs-ms-center { text-align: center; }
.gs-ms-f { padding: 5px 8px; border: 1px solid var(--gd-line); border-radius: 6px; font-size: 12px; color: var(--gd-muted); }
.gs-ms-b { padding: 6px 8px; border-radius: 6px; font-size: 12px; font-weight: 600; line-height: 1.25; text-align: center; }
.gs-ms-b.p { background: var(--gd-accent); color: var(--gd-on-accent); }
.gs-ms-b.s { border: 1px solid var(--gd-line); color: var(--gd-fg); }
.gs-ms-b.icon { display: flex; align-items: center; justify-content: center; gap: 6px; }
.gs-ms-b.icon .gs-glyph { width: 16px; height: 16px; }
.gs-ms-or { display: flex; align-items: center; gap: 8px; font-size: 11px; color: var(--gd-muted); }
.gs-ms-or::before, .gs-ms-or::after { content: ''; flex: 1; height: 1px; background: var(--gd-line-2); }
.gs-ms-row { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 6px; }
.gs-ms-who { display: flex; align-items: center; gap: 8px; padding: 6px 8px; border-radius: 8px; background: var(--gd-surface-2); font-size: 13px; line-height: 1.3; color: var(--gd-fg); }
.gs-ms-who > .gs-glyph { width: 22px; height: 22px; }
.gs-ms-perm { display: grid; gap: 4px; margin: 0; padding: 0; list-style: none; font-size: 12px; color: var(--gd-muted); }
.gs-ms-perm li { display: flex; align-items: center; gap: 6px; }
.gs-ms-perm .gs-glyph { width: 13px; height: 13px; color: var(--gd-good); }
.gs-ms-code { padding: 4px 0; font-family: var(--gd-mono); font-size: 17px; letter-spacing: 0.18em; text-align: center; color: var(--gd-fg); }

.gs-next { display: flex; align-items: center; gap: 8px; padding: 10px 14px; border: 1px solid var(--gd-accent-border); border-radius: 8px; background: var(--gd-accent-soft); color: var(--gd-fg); font-size: 14px; text-decoration: none; }
.gs-next:hover { border-color: var(--gd-accent); color: var(--gd-fg); }
.gs-next:focus-visible { outline: 2px solid var(--gd-accent); outline-offset: 2px; }
.gs-next-k { flex: none; font-weight: 600; color: var(--gd-accent); }
.gs-next-t { min-width: 0; font-weight: 600; }
.gs-next-arrow { margin-inline-start: auto; font-weight: 700; color: var(--gd-accent); }

@media (prefers-reduced-motion: no-preference) {
  .gs-badge { animation: gs-pop 0.35s ease-out 0.2s both; }
  .gs-node.fox .gs-tile { animation: gs-drop 0.4s ease-out 0.1s both; }
  .gs-link-chip { animation: gs-fade 0.3s ease-out 0.45s both; }
}
@keyframes gs-pop { from { transform: scale(0.4); opacity: 0; } to { transform: none; opacity: 1; } }
@keyframes gs-drop { from { transform: translateY(-6px); opacity: 0; } to { transform: none; opacity: 1; } }
@keyframes gs-fade { from { opacity: 0; } to { opacity: 1; } }
`;

export function PictureStyles() {
	return <style dangerouslySetInnerHTML={{ __html: CSS }} />;
}
