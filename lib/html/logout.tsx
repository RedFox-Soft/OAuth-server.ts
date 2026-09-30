import { renderToStaticMarkup } from 'react-dom/server';
import { createCache, extractStyle, StyleProvider } from '@ant-design/cssinjs';
import { Button, Form } from 'antd';
import { Card, Flex } from 'antd';
import { htmlResponse } from './csp.js';
import { versionedAsset } from './versionedAsset.js';

const cache = createCache();
/*
 * The confirmation address is handed in rather than read from `routeNames`: a root-relative
 * `/logout/confirm` sends a path-addressed bucket's confirmation to the default bucket, whose session
 * cookie holds none of this sign-out's state.
 */
function renderLogoutForm(secret: string, confirmAction: string) {
	return (
		<StyleProvider cache={cache}>
			<Flex
				justify="center"
				style={{
					display: 'flex',
					height: '100vh',
					alignItems: 'center',
					backgroundColor: '#f0f2f5'
				}}
			>
				<Card
					style={{
						width: 400,
						padding: 24,
						borderRadius: 12,
						boxShadow: '0 2px 8px rgba(0, 0, 0, 0.1)'
					}}
				>
					<div style={{ textAlign: 'center', marginBottom: 24 }}>
						<img
							src={versionedAsset('logo.svg')}
							alt="Logo"
							style={{ width: 120 }}
						/>
					</div>
					<div style={{ textAlign: 'center', marginBottom: 24, fontSize: 16 }}>
						<p>Do you want to sign-out?</p>
					</div>
					<Form
						action={confirmAction}
						component="form"
						method="post"
					>
						<input
							type="hidden"
							name="xsrf"
							value={secret}
						/>
						<Form.Item>
							<Flex gap="small">
								<Button
									block
									htmlType="button"
									className="logout logout-cancel"
								>
									No, stay signed in
								</Button>
								<Button
									block
									name="logout"
									type="primary"
									value="true"
									htmlType="submit"
									className="logout logout-submit"
									autoFocus
								>
									Yes, sign me out
								</Button>
							</Flex>
						</Form.Item>
					</Form>
				</Card>
			</Flex>
		</StyleProvider>
	);
}

/*
 * `postLogoutRedirectUri` is where confirming will send the browser, already checked against the
 * client's registration. It reaches the policy because `form-action` governs the submission's whole
 * redirect chain: with 'self' alone the browser blocked the 303 to the relying party after the session
 * had ended, and left the user on this page.
 */
export function logout(
	secret: string,
	confirmAction: string,
	postLogoutRedirectUri?: string
) {
	const form = renderLogoutForm(secret, confirmAction);
	const styleText = extractStyle(cache);

	const html = `<!DOCTYPE html>
<html><head>
  <title>Logging Out</title>
  <style>${styleText}</style>
</head><body>${renderToStaticMarkup(form)}</body></html>`;

	return htmlResponse(html, { handOffTo: postLogoutRedirectUri });
}
