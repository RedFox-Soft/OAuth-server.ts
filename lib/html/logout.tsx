import { renderToStaticMarkup } from 'react-dom/server';
import { createCache, extractStyle, StyleProvider } from '@ant-design/cssinjs';
import { Button, Form } from 'antd';
import { Card, Flex } from 'antd';

const cache = createCache();
function renderLogoutForm(secret: string) {
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
							src="/public/logo.svg"
							alt="Logo"
							style={{ width: 120 }}
						/>
					</div>
					<div style={{ textAlign: 'center', marginBottom: 24, fontSize: 16 }}>
						<p>Do you want to sign-out?</p>
					</div>
					<Form
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
									type="primary"
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

export function logout(secret: string) {
	const form = renderLogoutForm(secret);
	const styleText = extractStyle(cache);

	const html = `<!DOCTYPE html>
<html><head>
  <title>Logging Out</title>
  <style>${styleText}</style>
</head><body>${renderToStaticMarkup(form)}</body></html>`;

	return new Response(html, {
		headers: {
			'Content-Type': 'text/html; charset=utf-8'
		}
	});
}
