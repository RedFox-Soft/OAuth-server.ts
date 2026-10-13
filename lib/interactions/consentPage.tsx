import React from 'react';
import { Button, Card, Flex, Typography } from 'antd';
import {
	ClockCircleOutlined,
	CloudServerOutlined,
	EnvironmentOutlined,
	KeyOutlined,
	LaptopOutlined,
	MailOutlined,
	PhoneOutlined,
	TeamOutlined,
	UserOutlined,
	WarningOutlined
} from '@ant-design/icons';
import type {
	ConsentGroup,
	ConsentItem,
	ConsentView,
	DataCategory
} from './consentView.js';
import { CONSENT_TEXTS as T, joinList } from './consentTexts.js';
import { buildUILoginPath } from './buildUIPath.js';
import { DEFAULT_LOGO } from './logo.js';

const { Title, Paragraph, Text } = Typography;

/*
 * Icons are hidden from assistive technology everywhere on this page: antd labels each one with its
 * English component name ("mail", "key"), which a screen reader would read out in the middle of a
 * sentence. The text beside it carries the meaning; the icon only helps the eye find the line.
 */
const CATEGORY_ICON: Record<DataCategory, React.ReactNode> = {
	profile: <UserOutlined aria-hidden="true" />,
	profileName: <UserOutlined aria-hidden="true" />,
	profilePhoto: <UserOutlined aria-hidden="true" />,
	profileDetails: <UserOutlined aria-hidden="true" />,
	email: <MailOutlined aria-hidden="true" />,
	address: <EnvironmentOutlined aria-hidden="true" />,
	phone: <PhoneOutlined aria-hidden="true" />,
	groups: <TeamOutlined aria-hidden="true" />
};

const MUTED = 'rgba(0, 0, 0, 0.55)';

// Visible to a screen reader only, so a warning announces itself as one without a second visual label.
const hiddenText: React.CSSProperties = {
	position: 'absolute',
	width: 1,
	height: 1,
	overflow: 'hidden',
	clip: 'rect(0 0 0 0)',
	whiteSpace: 'nowrap'
};

// A host or a technical name: never translated by the browser, and broken anywhere rather than widening the page.
const codeStyle: React.CSSProperties = {
	fontFamily:
		"ui-monospace, 'Cascadia Mono', 'SFMono-Regular', Consolas, monospace",
	fontSize: 13,
	overflowWrap: 'anywhere'
};

function itemText(item: ConsentItem): string {
	if (item.category) return T.categories[item.category];
	if (item.text) return item.text;
	const codes = item.codes.join(', ');
	return item.resource ? T.resource.codesIn(codes, item.resource) : codes;
}

function Codes({ codes }: { codes: string[] }) {
	return (
		<Flex
			wrap
			gap={6}
		>
			{codes.map((code) => (
				<code
					key={code}
					lang="en"
					translate="no"
					style={{
						...codeStyle,
						padding: '1px 6px',
						borderRadius: 4,
						background: '#f6f7f9',
						border: '1px solid #e6e8eb'
					}}
				>
					{code}
				</code>
			))}
		</Flex>
	);
}

function TechnicalNames({ items }: { items: ConsentItem[] }) {
	const codes = items.flatMap((i) => i.codes);
	if (!codes.length) return null;
	return (
		<details style={{ marginTop: 4 }}>
			<summary style={{ cursor: 'pointer', fontSize: 12.5, color: MUTED }}>
				{T.resource.technicalNames}
			</summary>
			<div style={{ marginTop: 6 }}>
				<Codes codes={codes} />
			</div>
		</details>
	);
}

function ItemList({ items }: { items: ConsentItem[] }) {
	return (
		<ul style={{ margin: 0, paddingLeft: 0, listStyle: 'none' }}>
			{items.map((item) => (
				<li
					key={`${item.category ?? item.text ?? ''}:${item.codes.join(' ')}`}
					style={{ display: 'flex', gap: 8, alignItems: 'baseline' }}
				>
					<span style={{ width: 16, color: MUTED, flex: 'none' }}>
						{item.category ? CATEGORY_ICON[item.category] : '•'}
					</span>
					<span>{itemText(item)}</span>
				</li>
			))}
		</ul>
	);
}

function GroupBody({
	group,
	described,
	service
}: {
	group: ConsentGroup;
	described: boolean;
	service: string;
}) {
	return (
		<Flex
			vertical
			gap={8}
		>
			{group.items.length ? (
				described ? (
					<>
						<ItemList items={group.items} />
						{group.items.some((i) => !i.category) ? (
							<TechnicalNames items={group.items.filter((i) => !i.category)} />
						) : null}
					</>
				) : (
					<>
						<Text style={{ color: MUTED }}>
							{T.resource.undescribedAdministrator(service)}
						</Text>
						<Codes codes={group.items.flatMap((i) => i.codes)} />
					</>
				)
			) : null}
			{group.resources.map((resource) => (
				<div
					key={resource.indicator}
					style={{
						border: '1px solid #e6e8eb',
						borderRadius: 8,
						padding: '10px 12px'
					}}
				>
					<div style={{ display: 'flex', gap: 8, alignItems: 'baseline' }}>
						<span style={{ width: 16, color: MUTED, flex: 'none' }}>
							<CloudServerOutlined aria-hidden="true" />
						</span>
						<span>
							{T.resource.heading}{' '}
							{resource.name ? (
								<>
									<b>
										<bdi>{resource.name}</bdi>
									</b>{' '}
									—{' '}
								</>
							) : null}
							<span
								translate="no"
								style={{ ...codeStyle, color: MUTED }}
							>
								{resource.host}
							</span>
						</span>
					</div>
					<div style={{ paddingLeft: 24, marginTop: 6 }}>
						{described ? (
							<>
								<ul style={{ margin: 0, paddingLeft: 16 }}>
									{resource.items.map((item) => (
										<li key={item.codes.join(' ')}>{itemText(item)}</li>
									))}
								</ul>
								<TechnicalNames items={resource.items} />
							</>
						) : (
							<Flex
								vertical
								gap={6}
							>
								<Text style={{ color: MUTED }}>
									{T.resource.undescribedOwner(resource.name ?? resource.host)}
								</Text>
								<Codes codes={resource.items.flatMap((i) => i.codes)} />
							</Flex>
						)}
					</div>
				</div>
			))}
			{group.rar.map((block, index) => (
				<div
					key={`${block.label}:${index}`}
					style={{
						border: '1px solid #e6e8eb',
						borderRadius: 8,
						padding: '10px 12px'
					}}
				>
					<b>
						<bdi>{block.label}</bdi>
					</b>
					<ul style={{ margin: '4px 0 0', paddingLeft: 16 }}>
						{block.fields.map((f) => (
							<li key={f.field}>
								{`${T.rarFields[f.field]}: `}
								<bdi>{f.values}</bdi>
							</li>
						))}
					</ul>
				</div>
			))}
		</Flex>
	);
}

function isEmpty(group: ConsentGroup): boolean {
	return !group.items.length && !group.resources.length && !group.rar.length;
}

function Groups({
	groups,
	service
}: {
	groups: ConsentView['groups'];
	service: string;
}) {
	const sections: {
		key: string;
		title: string;
		group: ConsentGroup;
		described: boolean;
	}[] = [
		{ key: 'see', title: T.groups.see, group: groups.see, described: true },
		{ key: 'act', title: T.groups.act, group: groups.act, described: true },
		{
			key: 'other',
			title: T.groups.other,
			group: groups.other,
			described: false
		}
	];
	return (
		<>
			{sections
				.filter((s) => !isEmpty(s.group))
				.map((s) => (
					<section key={s.key}>
						<Title
							level={2}
							style={{ fontSize: 15, margin: '0 0 6px' }}
						>
							{s.title}
						</Title>
						<GroupBody
							group={s.group}
							described={s.described}
							service={service}
						/>
					</section>
				))}
		</>
	);
}

function Warning({
	tone,
	icon,
	children
}: {
	tone: 'warn' | 'danger';
	icon: React.ReactNode;
	children: React.ReactNode;
}) {
	const palette =
		tone === 'danger'
			? { bg: '#fff2f0', border: '#ffccc7', icon: '#a8071a' }
			: { bg: '#fffbe6', border: '#ffe58f', icon: '#ad6800' };
	return (
		<div
			style={{
				display: 'flex',
				gap: 10,
				padding: '10px 12px',
				borderRadius: 8,
				border: `1px solid ${palette.border}`,
				background: palette.bg
			}}
		>
			<span style={{ color: palette.icon, flex: 'none' }}>{icon}</span>
			<div>
				<span style={hiddenText}>{T.warning.hiddenPrefix} </span>
				{children}
			</div>
		</div>
	);
}

function WarningBlock({
	view,
	service
}: {
	view: ConsentView;
	service: string;
}) {
	const { warning, client, redirect, device } = view;
	if (!warning) return null;
	switch (warning.kind) {
		case 'admin':
			return (
				<Warning
					tone="danger"
					icon={<KeyOutlined aria-hidden="true" />}
				>
					<b style={{ color: '#a8071a' }}>{T.warning.adminTitle}</b>{' '}
					{T.warning.admin(service)}
				</Warning>
			);
		case 'loopback':
			return (
				<Warning
					tone="warn"
					icon={<LaptopOutlined aria-hidden="true" />}
				>
					{T.warning.loopbackBefore(service)}
					<bdi>{client.name}</bdi>
					{T.warning.loopbackAfter}
				</Warning>
			);
		case 'device':
			return (
				<Warning
					tone="warn"
					icon={<WarningOutlined aria-hidden="true" />}
				>
					{T.warning.deviceQuestion} {T.warning.deviceSent}
					{device ? ` ${T.warning.deviceRequested(device.requestedAgo)}` : ''}
				</Warning>
			);
		case 'unverified':
			return (
				<Warning
					tone="warn"
					icon={<WarningOutlined aria-hidden="true" />}
				>
					{T.warning.unverifiedBefore}
					<bdi>{client.name}</bdi>
					{redirect.host
						? T.warning.unverifiedAfter(redirect.host)
						: T.warning.unverifiedAfterNoHost}
					{warning.reasons.includes('host-mismatch')
						? ` ${T.warning.hostMismatch}`
						: ''}
				</Warning>
			);
	}
}

function Headline({ view, service }: { view: ConsentView; service: string }) {
	const { mode, client } = view;
	const own = client.tier === 'this-organization';
	return (
		<Title
			level={1}
			style={{ fontSize: 22, lineHeight: 1.3, margin: 0, textWrap: 'balance' }}
		>
			{mode === 'device' ? (
				T.headline.device
			) : own ? (
				mode === 'sign-in' ? (
					T.headline.signIn(client.name)
				) : (
					T.headline.ownAccess(client.name, service)
				)
			) : (
				<>
					{T.headline.appBefore}
					<bdi>{client.name}</bdi>
					{T.headline.appAfter}
				</>
			)}
		</Title>
	);
}

function HostBox({ view, service }: { view: ConsentView; service: string }) {
	const { redirect, client, mode } = view;
	const own = client.tier === 'this-organization';
	const box: React.CSSProperties = {
		...codeStyle,
		alignSelf: 'flex-start',
		maxWidth: '100%',
		padding: '3px 8px',
		border: '1px solid #e6e8eb',
		background: '#f6f7f9',
		borderRadius: 6
	};
	const label = (text: string) => (
		<span
			style={{
				fontFamily: 'inherit',
				color: MUTED,
				fontSize: 12,
				marginRight: 6
			}}
		>
			{text}
		</span>
	);
	return (
		<Flex
			vertical
			gap={4}
		>
			{redirect.kind === 'web' && redirect.host ? (
				<span
					translate="no"
					style={box}
				>
					{own ? null : label(T.host.label)}
					{redirect.host}
				</span>
			) : null}
			{redirect.documentHost ? (
				<span
					translate="no"
					style={box}
				>
					{label(T.host.documentLabel)}
					{redirect.documentHost}
				</span>
			) : null}
			{redirect.kind === 'private-use' && redirect.scheme ? (
				<span style={{ ...box, fontFamily: 'inherit', fontSize: 14 }}>
					{T.host.privateUse(redirect.scheme, service)}
				</span>
			) : null}
			{!own && mode !== 'device' ? (
				<Text style={{ color: MUTED, fontSize: 13 }}>
					{T.host.notChecked(service)}
				</Text>
			) : null}
		</Flex>
	);
}

function Body({ view, service }: { view: ConsentView; service: string }) {
	const { mode, compact, signInData, previouslyAllowed, nothingRequested } =
		view;

	if (nothingRequested === 'first') {
		return (
			<Paragraph style={{ margin: 0 }}>
				{T.nothingRequested.before}
				<bdi>{view.client.name}</bdi>
				{T.nothingRequested.after}
			</Paragraph>
		);
	}
	if (nothingRequested === 'repeat') {
		return (
			<Paragraph style={{ margin: 0 }}>
				{T.repeat.nothingNew} {joinList(previouslyAllowed.map(itemText))}.
			</Paragraph>
		);
	}

	if (compact) {
		const shared = signInData;
		return (
			<Flex
				vertical
				gap={8}
			>
				{shared.length ? (
					<>
						<Text>{T.signIn.shares(service)}</Text>
						<ItemList
							items={shared.map((category) => ({ category, codes: [] }))}
						/>
					</>
				) : (
					<Text>{T.signIn.confirmsIdentity(service)}</Text>
				)}
				{mode === 'sign-in' ? (
					<Text style={{ color: MUTED }}>{T.signIn.noPassword}</Text>
				) : null}
			</Flex>
		);
	}

	return (
		<Flex
			vertical
			gap={14}
		>
			{previouslyAllowed.length ? (
				<Text style={{ color: MUTED }}>
					{T.repeat.alreadyAllowed} {joinList(previouslyAllowed.map(itemText))}.{' '}
					{T.repeat.alsoAsks}
				</Text>
			) : null}
			<Groups
				groups={view.groups}
				service={service}
			/>
			{/* Long-lived sign-in alone lists no data, and a page saying nothing about what it shares reads as hiding it. */}
			{!previouslyAllowed.length &&
			isEmpty(view.groups.see) &&
			isEmpty(view.groups.act) &&
			isEmpty(view.groups.other) ? (
				<Text>{T.signIn.confirmsIdentity(service)}</Text>
			) : null}
		</Flex>
	);
}

export const ConsentPage: React.FC<ConsentView> = (view) => {
	const {
		uid,
		service: serviceInfo,
		logoSrc,
		account,
		canSwitchAccount,
		keepsAccessUntil,
		afterApproval,
		nothingRequested,
		redirect,
		mode,
		device
	} = view;
	const service = serviceInfo.displayName ?? serviceInfo.host;
	const nothingAtAll = nothingRequested === 'first';

	return (
		<Flex
			justify="center"
			align="center"
			style={{
				minHeight: '100vh',
				padding: 16,
				backgroundColor: '#f0f2f5',
				boxSizing: 'border-box'
			}}
		>
			<Card
				style={{
					width: '100%',
					maxWidth: 440,
					borderRadius: 12,
					boxShadow: '0 2px 8px rgba(0, 0, 0, 0.1)'
				}}
				styles={{ body: { padding: 'clamp(16px, 5vw, 28px)' } }}
			>
				<Flex
					vertical
					gap={16}
				>
					<Flex
						align="center"
						gap={10}
						style={{ paddingBottom: 12, borderBottom: '1px solid #f0f0f0' }}
					>
						<img
							src={logoSrc || DEFAULT_LOGO}
							alt=""
							style={{ height: 28, width: 'auto' }}
						/>
						<Text strong>{service}</Text>
					</Flex>

					<Headline
						view={view}
						service={service}
					/>

					{mode === 'device' && device ? (
						<Flex
							vertical
							gap={8}
						>
							<Text>{T.device.client}</Text>
							<div
								translate="no"
								style={{
									...codeStyle,
									fontSize: 22,
									letterSpacing: '0.12em',
									textAlign: 'center',
									padding: 10,
									border: '1px dashed #b0b8c4',
									borderRadius: 8
								}}
							>
								{device.userCode}
							</div>
						</Flex>
					) : (
						<HostBox
							view={view}
							service={service}
						/>
					)}

					<Text style={{ color: MUTED }}>
						{T.account.signedInAs} <Text strong>{account.label}</Text>
						{canSwitchAccount ? (
							<>
								{' · '}
								<a
									href={buildUILoginPath(uid)}
									style={{ whiteSpace: 'nowrap' }}
								>
									{T.account.switch}
								</a>
							</>
						) : null}
					</Text>

					<WarningBlock
						view={view}
						service={service}
					/>

					<Body
						view={view}
						service={service}
					/>

					{keepsAccessUntil ? (
						<div
							style={{
								display: 'flex',
								gap: 8,
								alignItems: 'baseline',
								paddingTop: 12,
								borderTop: '1px solid #f0f0f0'
							}}
						>
							<span style={{ color: MUTED, flex: 'none' }}>
								<ClockCircleOutlined aria-hidden="true" />
							</span>
							<span>{T.lifetime(keepsAccessUntil)}</span>
						</div>
					) : null}

					{afterApproval.length ? (
						<div
							style={{
								background: '#f6f7f9',
								borderRadius: 8,
								padding: '10px 12px'
							}}
						>
							<b>{T.repeat.afterApproval}</b>{' '}
							{joinList(afterApproval.map(itemText))}.
						</div>
					) : null}

					<form method="post">
						<input
							type="hidden"
							name="accountId"
							value={account.id}
						/>
						{/*
						 * Allow comes first in the document and is drawn on the right: on a wide screen the two
						 * sit side by side in the usual order, and on a narrow one they wrap with Allow on top.
						 * The same size either way, and neither label carries the app's name.
						 */}
						<Flex
							wrap
							gap={8}
							style={{ flexDirection: 'row-reverse' }}
						>
							<Button
								type="primary"
								htmlType="submit"
								name="action"
								value="allow"
								size="large"
								style={{ flex: '1 1 160px', minHeight: 44 }}
							>
								{nothingAtAll ? T.buttons.continue : T.buttons.allow}
							</Button>
							<Button
								htmlType="submit"
								name="action"
								value="cancel"
								size="large"
								style={{ flex: '1 1 160px', minHeight: 44 }}
							>
								{nothingAtAll ? T.buttons.cancel : T.buttons.deny}
							</Button>
						</Flex>
					</form>

					{mode === 'device' ? (
						<Text style={{ color: MUTED, textAlign: 'center' }}>
							{T.device.next}
						</Text>
					) : redirect.kind === 'loopback' ? (
						<Text style={{ color: MUTED, textAlign: 'center' }}>
							{T.next.loopback}
						</Text>
					) : null}
				</Flex>
			</Card>
		</Flex>
	);
};
