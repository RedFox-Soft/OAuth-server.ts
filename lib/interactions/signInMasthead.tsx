import { Flex, Typography } from 'antd';
import type { ReactNode } from 'react';
import { foxVar } from '../html/theme/palette.js';
import { DEFAULT_LOGO } from './logo.js';

/*
 * Where a sign-in leads, as its pages say it. `service` is the project being signed in to — its display name,
 * else its issuer's host — and is always present: a page that names nothing is a page anyone could have built.
 * `app` is present only for an application the project stands behind, under the rule its colour follows
 * (branding.ts): anyone can register an app and call it anything, and on a page with no warnings a name is a
 * claim the page makes for it.
 */
export interface SignInFace {
	service: string;
	app?: { name: string; logo?: string };
}

/*
 * The app's own logo, on a plain tile so a picture with no background of its own still reads as a tile and
 * not as part of the page. Named by the app's name: the image is who is asking, not decoration.
 */
export function ClientLogo({ src, name }: { src: string; name: string }) {
	return (
		<span
			style={{
				flex: 'none',
				display: 'block',
				width: 40,
				height: 40,
				padding: 3,
				boxSizing: 'border-box',
				background: foxVar('logo-plate'),
				border: `1px solid ${foxVar('logo-plate-border')}`,
				borderRadius: 8
			}}
		>
			<img
				src={src}
				alt={name}
				width={32}
				height={32}
				style={{ display: 'block', objectFit: 'contain' }}
			/>
		</span>
	);
}

/*
 * The top of every page of a sign-in: the server's mark and the project's name on one line, as the consent page
 * opens, then the application's logo beside the page's heading. The heading is the page's own words, chosen
 * by the page from the face it was given.
 */
export function SignInMasthead({
	face,
	logoSrc = DEFAULT_LOGO,
	heading
}: {
	face: SignInFace;
	logoSrc?: string;
	heading: ReactNode;
}) {
	return (
		<Flex
			vertical
			gap={16}
			style={{ marginBottom: 24 }}
		>
			<Flex
				align="center"
				gap={10}
				style={{
					paddingBottom: 12,
					borderBottom: `1px solid ${foxVar('divider')}`
				}}
			>
				<img
					src={logoSrc}
					alt=""
					style={{ height: 28, width: 'auto' }}
				/>
				<Typography.Text strong>{face.service}</Typography.Text>
			</Flex>
			<Flex
				gap={12}
				align="center"
			>
				{face.app?.logo && (
					<ClientLogo
						src={face.app.logo}
						name={face.app.name}
					/>
				)}
				<Typography.Title
					level={1}
					style={{
						fontSize: 22,
						lineHeight: 1.3,
						margin: 0,
						textWrap: 'balance'
					}}
				>
					{heading}
				</Typography.Title>
			</Flex>
		</Flex>
	);
}
