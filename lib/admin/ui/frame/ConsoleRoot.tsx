import { App, ConfigProvider } from 'antd';
import { ZeroRuntime } from '../../../html/zeroRuntime.js';
import type { AdminShellProps } from '../serverRender.js';
import { AcceptInvitation } from '../pages/AcceptInvitation.js';
import { Layout } from '../pages/Layout.js';
import { Setup } from '../pages/Setup.js';
import { FeedbackBridge } from './feedback.js';
import { InstanceHostProvider } from './instance.js';
import { MeProvider } from './me.js';
import { RouterProvider } from './router.js';
import { resolveAddress } from './routes.js';

/*
 * antd's default primary, #1677ff, is 4.1:1 behind a primary button's white label, below WCAG AA. The end-user pages
 * moved to #0958d9 already (lib/html/theme/palette.ts); the console takes the same blue, with a hover that stays above
 * 4.5:1 (5.2:1) rather than antd's lighter one (3.0:1). The precompiled antd.css reads these through its CSS variables.
 */
const CONSOLE_TOKENS = {
	colorPrimary: '#0958d9',
	colorPrimaryHover: '#1668dc',
	colorPrimaryActive: '#003eb3',
	colorLink: '#0958d9',
	colorLinkHover: '#1668dc',
	colorLinkActive: '#003eb3'
};

/*
 * The one tree both the server render and the client hydrate mount, so the two cannot disagree about
 * what wraps the page. antd's `App` is what makes `App.useApp()` — the console's only way to show a
 * message, a notification or a confirmation — available everywhere below it.
 */
export function ConsoleRoot({
	needsSetup,
	me,
	path,
	instanceHost
}: AdminShellProps) {
	const initialPath = path ?? '/admin';
	const resolved = resolveAddress(initialPath.split('?')[0] ?? initialPath);
	const isPublic = resolved.kind === 'page' && resolved.route.public;
	return (
		<ZeroRuntime>
			<ConfigProvider theme={{ token: CONSOLE_TOKENS }}>
				<App>
					<RouterProvider initialPath={initialPath}>
						<FeedbackBridge />
						{needsSetup ? (
							<Setup />
						) : isPublic ? (
							<AcceptInvitation />
						) : (
							<InstanceHostProvider value={instanceHost ?? ''}>
								<MeProvider initial={me}>
									<Layout />
								</MeProvider>
							</InstanceHostProvider>
						)}
					</RouterProvider>
				</App>
			</ConfigProvider>
		</ZeroRuntime>
	);
}
