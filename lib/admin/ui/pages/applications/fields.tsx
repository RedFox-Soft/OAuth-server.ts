import { useState } from 'react';
import {
	Button,
	ColorPicker,
	Input,
	Select,
	Space,
	Tag,
	Typography,
	Upload
} from 'antd';
import {
	LOGO_MAX_BYTES,
	LOGO_SIZE_MESSAGE
} from '../../../../consts/client_logo.js';
import { paintedAccent } from '../../../../html/theme/accent.js';

/*
 * The application's browser origins (specs/099). Validation is deliberately left to the server: it owns
 * the one rule shared with the request path, and its refusal names the offending value and the canonical
 * form it should have been. An application in the same bucket is usually the same product, so its list
 * can be copied in one step instead of retyped.
 */
export function OriginsField({
	value,
	onChange,
	siblings
}: {
	value?: string[];
	onChange?: (value: string[]) => void;
	siblings: { label: string; origins: string[] }[];
}) {
	const origins = value ?? [];
	const [draft, setDraft] = useState('');
	function add() {
		const next = draft.trim();
		setDraft('');
		if (next && !origins.includes(next)) onChange?.([...origins, next]);
	}
	return (
		<Space
			orientation="vertical"
			size={8}
			style={{ width: '100%' }}
		>
			<Space wrap>
				{origins.length === 0 && (
					<Typography.Text type="secondary">No origins</Typography.Text>
				)}
				{origins.map((origin) => (
					<Tag
						key={origin}
						closable
						onClose={() => onChange?.(origins.filter((o) => o !== origin))}
					>
						{origin}
					</Tag>
				))}
			</Space>
			<Space.Compact style={{ width: '100%' }}>
				<Input
					value={draft}
					placeholder="https://app.example.com"
					onChange={(e) => setDraft(e.target.value)}
					onPressEnter={(e) => {
						e.preventDefault();
						add();
					}}
				/>
				<Button onClick={add}>Add</Button>
			</Space.Compact>
			{siblings.length > 0 && (
				<Select<number>
					placeholder="Copy from another application of this project"
					style={{ width: '100%' }}
					value={null}
					options={siblings.map((sibling, index) => ({
						label: `${sibling.label} (${sibling.origins.length})`,
						value: index
					}))}
					onChange={(index) => {
						const picked = siblings.at(index);
						if (picked) {
							onChange?.([...new Set([...origins, ...picked.origins])]);
						}
					}}
				/>
			)}
		</Space>
	);
}

/*
 * The client's logo as the consent page will show it, read into a `data:` URL in the browser: the admin
 * API takes the image in the body, so no upload route exists. The size is checked here only to say so
 * sooner; what the bytes are is the server's decision.
 */
export function LogoField({
	value,
	onChange
}: {
	value?: string | null;
	onChange?: (value: string | null) => void;
}) {
	const [tooLarge, setTooLarge] = useState(false);
	return (
		<Space
			orientation="vertical"
			size={4}
		>
			<Space align="center">
				{value ? (
					<img
						src={value}
						alt="Current logo"
						width={40}
						height={40}
						style={{
							display: 'block',
							objectFit: 'contain',
							padding: 3,
							boxSizing: 'border-box',
							background: '#f6f7f9',
							border: '1px solid #e6e8eb',
							borderRadius: 8
						}}
					/>
				) : (
					<Typography.Text type="secondary">No logo</Typography.Text>
				)}
				<Upload
					accept="image/png,image/jpeg,image/webp"
					showUploadList={false}
					beforeUpload={(file) => {
						if (file.size > LOGO_MAX_BYTES) {
							setTooLarge(true);
							return false;
						}
						const reader = new FileReader();
						reader.onload = () => {
							if (typeof reader.result !== 'string') return;
							setTooLarge(false);
							onChange?.(reader.result);
						};
						reader.readAsDataURL(file);
						return false;
					}}
				>
					<Button>{value ? 'Replace' : 'Upload'}</Button>
				</Upload>
				{value ? (
					<Button onClick={() => onChange?.(null)}>Remove</Button>
				) : null}
			</Space>
			{tooLarge ? (
				<Typography.Text type="danger">{LOGO_SIZE_MESSAGE}</Typography.Text>
			) : null}
		</Space>
	);
}

/*
 * The application's colour, and what its sign-in pages will make of it: a primary button on a light page and on a
 * dark one, painted by the very code the pages use (lib/html/theme/accent.ts), so the preview is the page.
 */
export function PrimaryColorField({
	value,
	onChange
}: {
	value?: string | null;
	onChange?: (value: string | null) => void;
}) {
	const accent = value ? paintedAccent(value) : undefined;
	const tile = (background: string, fill: string, scheme: string) => (
		<span
			style={{
				display: 'inline-flex',
				alignItems: 'center',
				padding: 8,
				borderRadius: 8,
				background,
				border: '1px solid #e6e8eb'
			}}
		>
			<span
				role="img"
				aria-label={`Primary button on a ${scheme} page, ${fill}`}
				style={{
					padding: '4px 12px',
					borderRadius: 6,
					background: fill,
					color: '#ffffff'
				}}
			>
				Continue
			</span>
		</span>
	);
	return (
		<Space
			orientation="vertical"
			size={4}
		>
			<Space align="center">
				<ColorPicker
					value={value ?? undefined}
					format="hex"
					disabledAlpha
					disabledFormat
					showText={() => value ?? 'Server default'}
					onChangeComplete={(color) => onChange?.(color.toHexString())}
				/>
				{value ? (
					<Button onClick={() => onChange?.(null)}>Remove</Button>
				) : null}
			</Space>
			{accent ? (
				<Space align="center">
					{tile('#ffffff', accent.light.primary, 'light')}
					{tile('#141414', accent.dark.primary, 'dark')}
				</Space>
			) : null}
			{accent?.adjusted ? (
				<Typography.Text type="secondary">
					Adjusted for legibility — people will see the shades shown.
				</Typography.Text>
			) : null}
		</Space>
	);
}
