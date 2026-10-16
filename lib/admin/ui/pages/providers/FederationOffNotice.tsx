import type { CSSProperties } from 'react';
import { Alert } from 'antd';
import { Link } from '../../frame/router.js';
import { meCan, useMe } from '../../frame/me.js';

/*
 * Why a project's providers are not on its sign-in page: the instance switch `federation.enabled` is off, so
 * no provider button renders anywhere, whatever the project holds. Shown wherever an administrator looks for
 * those buttons — the providers list, a provider's page, the sign-in tab — because without it the page simply
 * lacks them and nothing says why, which is how a production deployment came to look broken.
 *
 * Only a super administrator can turn it on, so only they get the link; anyone else is told what to ask for,
 * by the name the Settings page shows rather than its dotted key.
 */
export function FederationOffNotice({ style }: { style?: CSSProperties }) {
	const { me } = useMe();
	const instance = meCan(me).instance;
	return (
		<Alert
			style={style}
			type="warning"
			showIcon
			title="These providers are not shown on the sign-in page"
			description={
				instance ? (
					<>
						Sign-in through an upstream identity provider is switched off on
						this instance, so no provider button appears for anyone.{' '}
						<Link href="/admin/settings?pane=signin-abuse">
							Turn it on in Settings → Sign-in &amp; abuse → Federation
						</Link>
						.
					</>
				) : (
					'Sign-in through an upstream identity provider is switched off on this instance, so no provider button appears for anyone. Ask an instance administrator to turn on Federation (Settings → Sign-in & abuse).'
				)
			}
		/>
	);
}
