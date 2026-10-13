/*
 * WCAG 2.2 contrast, computed one way for the palette, the antd token sets and their tests
 * (specs/096 contracts/palette.md). A translucent colour is first composited over what it is drawn on —
 * antd's text colours are rgba, and their contrast depends on the surface beneath them.
 */

type Rgba = [number, number, number, number];

function parse(colour: string): Rgba {
	const hex = /^#([0-9a-f]{3}|[0-9a-f]{6})$/i.exec(colour.trim());
	if (hex) {
		const six = hex[1].length === 3 ? hex[1].replace(/./g, '$&$&') : hex[1];
		const digits = six.match(/../g) ?? [];
		const [r, g, b] = digits.map((d) => parseInt(d, 16));
		return [r, g, b, 1];
	}
	const fn = /^rgba?\(([^)]+)\)$/i.exec(colour.trim());
	if (fn) {
		const [r, g, b, a = 1] = fn[1].split(',').map((p) => Number(p.trim()));
		return [r, g, b, a];
	}
	throw new TypeError(`not a colour this module reads: ${colour}`);
}

function format([r, g, b]: Rgba): string {
	return `#${[r, g, b]
		.map((v) => Math.round(v).toString(16).padStart(2, '0'))
		.join('')}`;
}

// The colour a translucent `top` shows as over an opaque `base`, as an opaque hex.
export function composite(top: string, base: string): string {
	const [r, g, b, a] = parse(top);
	const under = parse(base);
	return format([
		r * a + under[0] * (1 - a),
		g * a + under[1] * (1 - a),
		b * a + under[2] * (1 - a),
		1
	]);
}

function luminance(colour: string): number {
	const [r, g, b] = parse(colour).map((v) => {
		const c = v / 255;
		return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
	});
	return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

export function contrastRatio(foreground: string, background: string): number {
	const fg = luminance(composite(foreground, background));
	const bg = luminance(background);
	return (Math.max(fg, bg) + 0.05) / (Math.min(fg, bg) + 0.05);
}

export function relativeLuminance(colour: string): number {
	return luminance(colour);
}
