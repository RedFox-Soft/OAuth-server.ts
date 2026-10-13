import { Button, Form } from 'antd';
import { Card, Flex } from 'antd';
import { htmlResponse } from './csp.js';
import { versionedAsset } from './versionedAsset.js';
import { foxVar } from './theme/palette.js';
import { renderEndUserTree } from './theme/dark.js';

/*
 * The confirmation address is handed in rather than read from `routeNames`: a root-relative
 * `/logout/confirm` sends a path-addressed bucket's confirmation to the default bucket, whose session
 * cookie holds none of this sign-out's state.
 */
function renderLogoutForm(secret: string, confirmAction: string) {
	return (
		<>
			<Flex
				justify="center"
				style={{
					display: 'flex',
					height: '100vh',
					padding: '0 16px',
					boxSizing: 'border-box',
					alignItems: 'center',
					backgroundColor: foxVar('page')
				}}
			>
				<Card
					style={{
						width: '100%',
						maxWidth: 400,
						padding: 24,
						borderRadius: 12,
						boxShadow: `0 2px 8px ${foxVar('shadow')}`
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
							<Flex
								gap="small"
								wrap
							>
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
		</>
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
	// Rendered before extracting, and not re-wrapped — for the reasons given at `logoutSuccess`.
	const page = renderEndUserTree(renderLogoutForm(secret, confirmAction));

	const html = `<!DOCTYPE html>
<html><head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Logging Out</title>
  ${page.head}
</head><body>${page.html}</body></html>`;

	return htmlResponse(html, { handOffTo: postLogoutRedirectUri });
}
