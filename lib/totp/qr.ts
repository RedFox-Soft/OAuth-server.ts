import { Ecc, QrCode } from '@rc-component/qrcode/lib/libs/qrcodegen.js';
import { generatePath } from '@rc-component/qrcode/lib/utils.js';

import { esc } from '../html/escape.js';

/*
 * A QR code as inline SVG, for the person's own two-step verification page (specs/126 research R12), which is plain
 * and runs no script. The encoder is the one the sign-in page's antd QR already ships with; only its pure functions
 * are used, so no React renders here.
 *
 * Black on white whatever the colour scheme — an authenticator app's camera reads dark modules on a light plate —
 * with the four-module quiet zone the QR specification asks for. Medium error correction: the URI it carries is
 * short enough that it still fits a size a phone reads at arm's length.
 */
const QUIET_ZONE = 4;

export function qrSvg(text: string, label: string, pixels = 192): string {
	const code = QrCode.encodeText(text, Ecc.MEDIUM);
	const cells = code.size + QUIET_ZONE * 2;
	const path = generatePath(code.getModules(), QUIET_ZONE);
	return [
		`<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-label="${esc(label)}" width="${pixels}" height="${pixels}" viewBox="0 0 ${cells} ${cells}" shape-rendering="crispEdges">`,
		`<path fill="#FFFFFF" d="M0,0 h${cells}v${cells}H0z"/>`,
		`<path fill="#000000" d="${esc(path)}"/>`,
		`</svg>`
	].join('');
}
