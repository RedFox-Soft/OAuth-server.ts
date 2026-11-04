import type { CSSProperties } from 'react';
import type {
	GuideActor,
	GuidePart,
	ProblemMark
} from '../../../../consts/situation_guide.js';
import { GUIDE_ACTOR_PARTS } from '../../../../situation_guide/options.js';
import {
	GUIDE_FIXED,
	GUIDE_MARKS,
	GUIDE_PARTS
} from '../../../../situation_guide/parts.js';
import type { GuideStatus } from './targets.js';

/*
 * One drawing of the guide, from lib/situation_guide/parts.ts: a part, a problem mark, or the check that replaces a
 * mark. The console keeps no drawing of its own, so it shows what the site shows. Decoration: a label beside it says
 * the same in words.
 */
export function Glyph({
	part,
	mark,
	strokeWidth = 1.75,
	size,
	style
}: {
	part?: GuidePart;
	mark?: ProblemMark;
	strokeWidth?: number;
	size?: number;
	style?: CSSProperties;
}) {
	const glyph = part
		? GUIDE_PARTS[part]
		: mark
			? GUIDE_MARKS[mark]
			: GUIDE_FIXED;
	return (
		<svg
			className="gs-glyph"
			viewBox={glyph.viewBox}
			fill="none"
			stroke="currentColor"
			strokeWidth={strokeWidth}
			strokeLinecap="round"
			strokeLinejoin="round"
			aria-hidden="true"
			focusable="false"
			style={size ? { width: size, height: size, ...style } : style}
		>
			{glyph.paths.map((d) => (
				<path
					key={d}
					d={d}
				/>
			))}
		</svg>
	);
}

/* The small picture on an option: its answer's parts (lib/situation_guide/options.ts), joined by a short line. */
export function Thumb({
	parts,
	small = false
}: {
	parts: readonly GuidePart[];
	small?: boolean;
}) {
	return (
		<span
			className={`gs-thumb${small ? ' sm' : ''}`}
			aria-hidden="true"
		>
			{parts.map((part, i) => (
				<span
					key={`${part}${String(i)}`}
					className="gs-thumb-part"
				>
					{i > 0 && <i className="gs-thumb-link" />}
					<Glyph part={part} />
				</span>
			))}
		</span>
	);
}

/* Question 1's option: the actor, with what it works at in a small tile on its corner. */
export function ActorThumb({ actor }: { actor: GuideActor }) {
	const [main, at] = GUIDE_ACTOR_PARTS[actor];
	return (
		<span
			className="gs-actor"
			aria-hidden="true"
		>
			<Glyph
				part={main}
				strokeWidth={1.5}
			/>
			<span className="gs-actor-at">
				<Glyph part={at} />
			</span>
		</span>
	);
}

/*
 * What an answer's button does for this viewer, as a glyph and a word, the same on the answer, its option and its row
 * in the table. The word carries the meaning; the glyph lets them be told apart at a glance down a column.
 */
export function StatusMark({
	status,
	size = 'sm'
}: {
	status: GuideStatus;
	size?: 'sm' | 'md';
}) {
	return (
		<span className={`gs-status ${status.tone} ${size}`}>
			{status.glyph === 'fixed' ? (
				<span className="gs-status-dot">
					<Glyph strokeWidth={3} />
				</span>
			) : (
				<Glyph
					part={status.glyph}
					strokeWidth={2}
				/>
			)}
			<span>{status.word}</span>
		</span>
	);
}
