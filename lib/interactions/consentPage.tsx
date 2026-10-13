import React from 'react';
import { Button, Card, Checkbox, Flex, Typography } from 'antd';
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
import { foxVar } from '../html/theme/palette.js';

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

const MUTED = foxVar('text-muted');

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
						background: foxVar('box'),
						border: `1px solid ${foxVar('box-border')}`
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

function RefusedBefore({ item }: { item: Pick<ConsentItem, 'refusedBefore'> }) {
	return item.refusedBefore ? (
		<div style={{ fontSize: 12.5, color: MUTED }}>
			{T.choices.refusedBefore}
		</div>
	) : null;
}

/*
 * A permission the person may leave out. The whole row is the checkbox's label, so a tap anywhere on it
 * toggles the box, and the text is the box's accessible name. A plain form field: it posts without script.
 */
function ChoiceRow({
	choiceKey,
	refusedBefore,
	icon,
	children
}: {
	choiceKey: string;
	refusedBefore?: true;
	icon?: React.ReactNode;
	children: React.ReactNode;
}) {
	return (
		<li style={{ listStyle: 'none' }}>
			<Checkbox
				value={choiceKey}
				style={{ display: 'flex', alignItems: 'center', minHeight: 44 }}
			>
				<span style={{ display: 'flex', gap: 8, alignItems: 'baseline' }}>
					{icon ? (
						<span style={{ width: 16, color: MUTED, flex: 'none' }}>
							{icon}
						</span>
					) : null}
					<span>
						{children}
						<RefusedBefore item={{ refusedBefore }} />
					</span>
				</span>
			</Checkbox>
		</li>
	);
}

/*
 * The one group every row belongs to. In antd a checkbox's `value` means something only inside a
 * `Checkbox.Group` — alone it warns that `value` is not a prop and asks for `checked` — and the group is what
 * names each box `allow`, so the ticked keys post with the form, script or not. It lays out as if it were not
 * there and announces nothing: the rows sit under the page's own headings, which already say what they are.
 */
function ChoiceGroup({
	active,
	children
}: {
	active: boolean;
	children: React.ReactNode;
}) {
	return active ? (
		<Checkbox.Group
			name="allow"
			role="none"
			style={{ display: 'contents' }}
		>
			{children}
		</Checkbox.Group>
	) : (
		<>{children}</>
	);
}

function itemKey(item: ConsentItem): string {
	return `${item.category ?? item.text ?? ''}:${item.codes.join(' ')}`;
}

function ItemList({ items }: { items: ConsentItem[] }) {
	return (
		<ul style={{ margin: 0, paddingLeft: 0, listStyle: 'none' }}>
			{items.map((item) =>
				item.choice ? (
					<ChoiceRow
						key={itemKey(item)}
						choiceKey={item.choice.key}
						refusedBefore={item.refusedBefore}
						icon={item.category ? CATEGORY_ICON[item.category] : undefined}
					>
						{itemText(item)}
					</ChoiceRow>
				) : (
					<li
						key={itemKey(item)}
						style={{ display: 'flex', gap: 8, alignItems: 'baseline' }}
					>
						<span style={{ width: 16, color: MUTED, flex: 'none' }}>
							{item.category ? CATEGORY_ICON[item.category] : '•'}
						</span>
						<span>
							{itemText(item)}
							<RefusedBefore item={item} />
						</span>
					</li>
				)
			)}
		</ul>
	);
}

/* Undescribed codes: chips when there is nothing to say about any one of them, one row each otherwise. */
function UndescribedCodes({ items }: { items: ConsentItem[] }) {
	if (!items.some((i) => i.choice || i.refusedBefore)) {
		return <Codes codes={items.flatMap((i) => i.codes)} />;
	}
	return (
		<ul style={{ margin: 0, paddingLeft: 0 }}>
			{items.map((item) =>
				item.choice ? (
					<ChoiceRow
						key={itemKey(item)}
						choiceKey={item.choice.key}
						refusedBefore={item.refusedBefore}
					>
						<Codes codes={item.codes} />
					</ChoiceRow>
				) : (
					<li
						key={itemKey(item)}
						style={{ listStyle: 'none' }}
					>
						<Codes codes={item.codes} />
						<RefusedBefore item={item} />
					</li>
				)
			)}
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
						<UndescribedCodes items={group.items} />
					</>
				)
			) : null}
			{group.resources.map((resource) => (
				<div
					key={resource.indicator}
					style={{
						border: `1px solid ${foxVar('box-border')}`,
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
								{resource.items.some((i) => i.choice) ? (
									<ItemList items={resource.items} />
								) : (
									<ul style={{ margin: 0, paddingLeft: 16 }}>
										{resource.items.map((item) => (
											<li key={item.codes.join(' ')}>
												{itemText(item)}
												<RefusedBefore item={item} />
											</li>
										))}
									</ul>
								)}
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
								<UndescribedCodes items={resource.items} />
							</Flex>
						)}
					</div>
				</div>
			))}
			{group.rar.map((block, index) => (
				<div
					key={`${block.label}:${index}`}
					style={{
						border: `1px solid ${foxVar('box-border')}`,
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
			? {
					bg: foxVar('danger-bg'),
					border: foxVar('danger-border'),
					icon: foxVar('danger-strong')
				}
			: {
					bg: foxVar('warn-bg'),
					border: foxVar('warn-border'),
					icon: foxVar('warn-icon')
				};
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
					<b style={{ color: foxVar('danger-strong') }}>
						{T.warning.adminTitle}
					</b>{' '}
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

/*
 * The app's own pages, which the server decided are on the app's own site. A new tab told nothing about
 * this page: no referrer, and no handle back to it. Darker than antd's link blue, which is under 4.5:1 on
 * white at this size.
 */
function AppLinks({
	name,
	links
}: {
	name: string;
	links: NonNullable<ConsentView['links']>;
}) {
	const entries = [
		links.policy ? { href: links.policy, after: T.links.policyAfter } : null,
		links.terms ? { href: links.terms, after: T.links.termsAfter } : null
	].filter((entry) => entry !== null);
	return (
		<nav aria-label={T.links.label(name)}>
			<Flex
				wrap
				justify="center"
				gap="0 12px"
				style={{ fontSize: 13 }}
			>
				{entries.map(({ href, after }) => (
					<a
						key={href + after}
						href={href}
						target="_blank"
						rel="noopener noreferrer"
						style={{
							display: 'inline-block',
							lineHeight: '24px',
							textAlign: 'center',
							color: foxVar('link')
						}}
					>
						<bdi>{name}</bdi>
						{after}
						<span aria-hidden="true">&nbsp;↗</span>
						<span style={hiddenText}>{T.links.external}</span>
					</a>
				))}
			</Flex>
		</nav>
	);
}

/*
 * The app's own logo, on a plain tile so a picture with no background of its own still reads as a tile and
 * not as part of the page. Named by the app's name: the image is who is asking, not decoration.
 */
function ClientLogo({ src, name }: { src: string; name: string }) {
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
		border: `1px solid ${foxVar('box-border')}`,
		background: foxVar('box'),
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
			{view.choices?.fixed.length ? (
				<section>
					<Title
						level={2}
						style={{ fontSize: 15, margin: '0 0 6px' }}
					>
						{T.choices.fixedHeading}
					</Title>
					<ItemList items={view.choices.fixed} />
				</section>
			) : null}
			<Groups
				groups={view.groups}
				service={service}
			/>
			{view.choices?.rarTogether ? (
				<Text style={{ color: MUTED }}>{T.choices.rarTogether}</Text>
			) : null}
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
				backgroundColor: foxVar('page'),
				boxSizing: 'border-box'
			}}
		>
			<Card
				style={{
					width: '100%',
					maxWidth: 440,
					borderRadius: 12,
					boxShadow: `0 2px 8px ${foxVar('shadow')}`
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
						style={{
							paddingBottom: 12,
							borderBottom: `1px solid ${foxVar('divider')}`
						}}
					>
						<img
							src={logoSrc || DEFAULT_LOGO}
							alt=""
							style={{ height: 28, width: 'auto' }}
						/>
						<Text strong>{service}</Text>
					</Flex>

					{view.client.logo ? (
						<Flex
							gap={12}
							align="flex-start"
						>
							<ClientLogo
								src={view.client.logo}
								name={view.client.name}
							/>
							<Headline
								view={view}
								service={service}
							/>
						</Flex>
					) : (
						<Headline
							view={view}
							service={service}
						/>
					)}

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
									border: `1px dashed ${foxVar('code-border')}`,
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

					{/*
					 * One form from the permissions to the buttons, laid out as if it were not there: the checkboxes
					 * live in the groups above the buttons and must post with them, without relying on script.
					 */}
					<form
						method="post"
						style={{ display: 'contents' }}
					>
						<ChoiceGroup active={!!view.choices}>
							<Body
								view={view}
								service={service}
							/>

							{view.offline ? (
								<ul
									style={{
										margin: 0,
										padding: '12px 0 0',
										borderTop: `1px solid ${foxVar('divider')}`
									}}
								>
									<ChoiceRow
										choiceKey={view.offline.key}
										refusedBefore={view.offline.refusedBefore}
										icon={<ClockCircleOutlined aria-hidden="true" />}
									>
										{T.choices.offline}
										{keepsAccessUntil ? (
											<div style={{ fontSize: 12.5, color: MUTED }}>
												{T.choices.offlineUntil(keepsAccessUntil)}
											</div>
										) : null}
									</ChoiceRow>
								</ul>
							) : keepsAccessUntil ? (
								<div
									style={{
										display: 'flex',
										gap: 8,
										alignItems: 'baseline',
										paddingTop: 12,
										borderTop: `1px solid ${foxVar('divider')}`
									}}
								>
									<span style={{ color: MUTED, flex: 'none' }}>
										<ClockCircleOutlined aria-hidden="true" />
									</span>
									<span>{T.lifetime(keepsAccessUntil)}</span>
								</div>
							) : null}
						</ChoiceGroup>

						{afterApproval.length ? (
							<div
								style={{
									background: foxVar('box'),
									borderRadius: 8,
									padding: '10px 12px'
								}}
							>
								<b>{T.repeat.afterApproval}</b>{' '}
								{joinList(afterApproval.map(itemText))}
								{view.afterApprovalDependsOnChoice
									? `, ${T.choices.afterApprovalRest}`
									: ''}
								.
							</div>
						) : null}

						<div>
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
						</div>
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

					{view.links ? (
						<AppLinks
							name={view.client.name}
							links={view.links}
						/>
					) : null}

					{/* This server's own page, so the same tab: nothing here leads to the app's site (specs/095). */}
					{view.revokeHint ? (
						<Text
							style={{
								color: MUTED,
								textAlign: 'center',
								fontSize: 13,
								lineHeight: '24px'
							}}
						>
							{T.revokeHint.before}
							<a
								href={view.revokeHint.href}
								style={{ color: foxVar('link'), display: 'inline-block' }}
							>
								{T.revokeHint.link}
							</a>
							{T.revokeHint.after}
						</Text>
					) : null}
				</Flex>
			</Card>
		</Flex>
	);
};
