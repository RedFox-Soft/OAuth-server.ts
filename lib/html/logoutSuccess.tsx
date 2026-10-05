import { renderToStaticMarkup } from 'react-dom/server';
import { createCache, extractStyle, StyleProvider } from '@ant-design/cssinjs';
import { Card, Flex } from 'antd';
import { htmlResponse } from './csp.js';
import { versionedAsset } from './versionedAsset.js';

const cache = createCache();
function renderLogoutForm() {
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
						<p>You have been signed out successfully</p>
					</div>
				</Card>
			</Flex>
		</StyleProvider>
	);
}

/*
 * Rendered before the styles are extracted: cssinjs registers a component's styles while it renders, so
 * extracting first left the first page after a restart unstyled and every later one wearing whatever
 * earlier renders had registered. `extractStyle` returns complete `<style>` elements, which is why they
 * are not wrapped in another.
 */
export function logoutSuccess() {
	const body = renderToStaticMarkup(renderLogoutForm());
	const styleText = extractStyle(cache);

	const html = `<!DOCTYPE html>
<html><head>
  <title>Logging Out</title>
  ${styleText}
</head><body>${body}</body></html>`;

	return htmlResponse(html);
}
