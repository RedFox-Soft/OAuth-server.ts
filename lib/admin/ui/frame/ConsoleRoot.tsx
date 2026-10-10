import { App } from 'antd';
import { ZeroRuntime } from '../../../html/zeroRuntime.js';
import type { AdminShellProps } from '../serverRender.js';
import { AcceptInvitation } from '../pages/AcceptInvitation.js';
import { Layout } from '../pages/Layout.js';
import { Setup } from '../pages/Setup.js';
import { FeedbackBridge } from './feedback.js';
import { MeProvider } from './me.js';
import { RouterProvider } from './router.js';
import { resolveAddress } from './routes.js';

/*
 * The one tree both the server render and the client hydrate mount, so the two cannot disagree about
 * what wraps the page. antd's `App` is what makes `App.useApp()` — the console's only way to show a
 * message, a notification or a confirmation — available everywhere below it.
 */
export function ConsoleRoot({ needsSetup, me, path }: AdminShellProps) {
	const initialPath = path ?? '/admin';
	const resolved = resolveAddress(initialPath.split('?')[0] ?? initialPath);
	const isPublic = resolved.kind === 'page' && resolved.route.public;
	return (
		<ZeroRuntime>
			<App>
				<RouterProvider initialPath={initialPath}>
					<FeedbackBridge />
					{needsSetup ? (
						<Setup />
					) : isPublic ? (
						<AcceptInvitation />
					) : (
						<MeProvider initial={me}>
							<Layout />
						</MeProvider>
					)}
				</RouterProvider>
			</App>
		</ZeroRuntime>
	);
}
