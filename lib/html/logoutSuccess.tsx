import { Card, Flex } from 'antd';
import { htmlResponse } from './csp.js';
import { esc } from './escape.js';
import { versionedAsset } from './versionedAsset.js';
import { foxVar } from './theme/palette.js';
import { renderEndUserTree } from './theme/dark.js';
import type { Language } from '../i18n/languages.js';
import { PAGES_TEXTS } from '../i18n/texts/pages/index.js';

function renderLogoutForm(language: Language) {
	const t = PAGES_TEXTS[language].logoutSuccess;
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
							alt={t.logoAlt}
							style={{ width: 120 }}
						/>
					</div>
					<div style={{ textAlign: 'center', marginBottom: 24, fontSize: 16 }}>
						<p>{t.message}</p>
					</div>
				</Card>
			</Flex>
		</>
	);
}

/*
 * renderEndUserTree renders before it extracts: cssinjs registers a component's styles while it renders, so
 * extracting first left the first page after a restart unstyled. Its <head> part is complete `<style>`
 * elements, which is why they are not wrapped in another.
 */
export function logoutSuccess(language: Language = 'en') {
	const page = renderEndUserTree(renderLogoutForm(language), { language });

	const html = `<!DOCTYPE html>
<html lang="${language}"><head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${esc(PAGES_TEXTS[language].logoutSuccess.title)}</title>
  ${page.head}
</head><body>${page.html}</body></html>`;

	return htmlResponse(html, { language });
}
