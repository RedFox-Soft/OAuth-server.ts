import type { MouseEvent, ReactNode } from 'react';
import { Alert, Button, Card, Flex, Tag, Typography } from 'antd';
import { CopyOutlined, ExportOutlined } from '@ant-design/icons';
import {
	GUIDE_EXAMPLES,
	guideSituation,
	type GuidePreview,
	type GuideSituation
} from '../../../../consts/situation_guide.js';
import {
	renderPrompt,
	type GuideViewer
} from '../../../../situation_guide/availability.js';
import { useFeedback } from '../../frame/feedback.js';
import { useInstanceHost } from '../../frame/instance.js';
import { Link, useNavigate } from '../../frame/router.js';
import { bucketHref } from '../../frame/routes.js';
import { FEATURE_LABEL, limitReachedText } from '../../planText.js';
import { situation as presetOf } from '../applications/situations.js';
import { PLAN_CARD_ID } from '../BucketPlanCard.js';
import { Glyph, StatusMark } from './Part.js';
import { PictureStyles, Strip } from './Scene.js';
import { SequenceDiagram, useDiagramPalette } from './SequenceDiagram.js';
import {
	actionFor,
	leavesConsole,
	statusOf,
	type GuideAction
} from './targets.js';

/*
 * One guide answer, whole: what the situation is, then the problem, the fix and what the person gets in three
 * pictures (Scene.tsx, drawn from lib/situation_guide/scene.ts as the site draws them), the one button that sets it
 * up, what usually comes next, how it runs step by step, what the form fills in, the limits, and a prompt for an agent.
 *
 * A situation is never hidden for a viewer who cannot set it up here: the answer is shown in full and only its
 * button changes (`actionFor`), so nobody is offered a form the route would refuse.
 *
 * `compact` keeps the parts that decide, the pictures and the limits among them, and drops the reference one (what is
 * filled in), for a place that shows the answer inside another page.
 */

type Persona = 'person' | 'program' | 'agent' | 'enterprise';

const PERSONA: Record<Persona, string> = {
	person: 'A person',
	program: 'A program',
	agent: 'An AI agent',
	enterprise: 'Enterprise'
};

function personaOf(s: GuideSituation): Persona {
	if (s.tab === 'enterprise') return 'enterprise';
	if (s.ask) return s.ask.actor;
	if (s.lanes.some((l) => l.kind === 'agent')) return 'agent';
	if (s.lanes.some((l) => l.kind === 'person')) return 'person';
	return 'program';
}

const SELF_HOSTING = 'https://foxauth.dev/docs/deploy/';

/* A button that goes somewhere: through the console's router inside it, in a new tab outside it. */
export function GoButton({
	href,
	primary,
	children
}: {
	href: string;
	primary?: boolean;
	children: ReactNode;
}) {
	const navigate = useNavigate();
	if (leavesConsole(href)) {
		return (
			<Button
				type={primary ? 'primary' : 'default'}
				href={href}
				target="_blank"
				rel="noopener noreferrer"
				icon={<ExportOutlined />}
				iconPlacement="end"
			>
				{children}
			</Button>
		);
	}
	const onClick = (event: MouseEvent<HTMLElement>) => {
		if (
			event.button !== 0 ||
			event.metaKey ||
			event.ctrlKey ||
			event.shiftKey ||
			event.altKey
		) {
			return;
		}
		event.preventDefault();
		void navigate(href);
	};
	return (
		<Button
			type={primary ? 'primary' : 'default'}
			href={href}
			onClick={onClick}
		>
			{children}
		</Button>
	);
}

function Destination({ href }: { href: string }) {
	return (
		<Typography.Text
			type="secondary"
			style={{ fontSize: 12, overflowWrap: 'anywhere' }}
		>
			Opens {href}
			{leavesConsole(href) ? ', in a new tab' : ''}
		</Typography.Text>
	);
}

function settingsList(settings: string[], last: 'and' | 'or'): ReactNode {
	return settings.map((key, i) => (
		<span key={key}>
			{i > 0 ? (i === settings.length - 1 ? ` ${last} ` : ', ') : ''}
			<Typography.Text code>{key}</Typography.Text>
		</span>
	));
}

/*
 * To the project's own Plan card on its Overview, which is true on any server: a plans page on foxauth.dev would be
 * the wrong one on a server someone else hosts. On the Overview itself (the empty project's guide card) it scrolls.
 */
function PlanCardButton({ bucketId }: { bucketId: string }) {
	const navigate = useNavigate();
	const href = `${bucketHref(bucketId)}#${PLAN_CARD_ID}`;
	const onClick = (event: MouseEvent<HTMLElement>) => {
		if (
			event.button !== 0 ||
			event.metaKey ||
			event.ctrlKey ||
			event.shiftKey ||
			event.altKey
		) {
			return;
		}
		event.preventDefault();
		const card = document.getElementById(PLAN_CARD_ID);
		if (card) card.scrollIntoView({ block: 'start' });
		else void navigate(href);
	};
	return (
		<Button
			href={href}
			onClick={onClick}
		>
			See the project’s plan
		</Button>
	);
}

/* The button, or what stands in for it, and the mark that says why. */
function Action({
	bucketId,
	action,
	viewer,
	scheduled
}: {
	bucketId: string;
	action: GuideAction;
	viewer: GuideViewer;
	scheduled: boolean;
}) {
	if (action.kind === 'go') {
		return (
			<Flex
				vertical
				gap={6}
				align="flex-start"
			>
				<GoButton
					href={action.href}
					primary
				>
					{action.label}
				</GoButton>
				<Destination href={action.href} />
			</Flex>
		);
	}
	if (action.kind === 'needsAddress') {
		return (
			<Flex
				vertical
				gap={6}
				align="flex-start"
			>
				<Typography.Text>
					{action.what === 'page'
						? 'The project serves this page at its own address, and it has none yet.'
						: 'This project has no address of its own yet, so it is not an issuer of its own: what this sets up would run at the server’s own address instead.'}{' '}
					First give the project an address on its Settings.
				</Typography.Text>
				<GoButton
					href={action.href}
					primary
				>
					Open Settings
				</GoButton>
			</Flex>
		);
	}
	const availability = action.availability;
	switch (availability.state) {
		case 'switchedOff': {
			const hosted = viewer.features.plans;
			const anyOf = availability.anyOf === true;
			return (
				<Alert
					type="warning"
					showIcon
					title="Switched on in the server’s settings"
					description={
						viewer.superAdmin ? (
							<Flex
								vertical
								gap={8}
								align="flex-start"
							>
								<span>
									This server has {settingsList(availability.settings, 'and')}{' '}
									switched off.{' '}
									{anyOf
										? 'Any one of them is enough: switch one on in Settings, then come back here.'
										: 'Switch it on in Settings, then come back here.'}
								</span>
								<GoButton
									href={`/admin/settings?pane=${encodeURIComponent(availability.pane)}`}
								>
									Open the setting
								</GoButton>
							</Flex>
						) : hosted ? (
							'Not switched on for this service.'
						) : (
							<span>
								Ask your super administrator to switch on{' '}
								{settingsList(availability.settings, anyOf ? 'or' : 'and')}.
							</span>
						)
					}
				/>
			);
		}
		case 'notOnPlan':
			return (
				<Alert
					type="info"
					showIcon
					title="Not on your plan"
					description={
						<Flex
							vertical
							gap={8}
							align="flex-start"
						>
							<span>
								{(FEATURE_LABEL as Record<string, string | undefined>)[
									availability.feature
								] ?? availability.feature}{' '}
								is not part of this project’s plan.
							</span>
							<PlanCardButton bucketId={bucketId} />
						</Flex>
					}
				/>
			);
		case 'planLimit':
			return (
				<Alert
					type="info"
					showIcon
					title="The plan’s limit is reached"
					description={
						<Flex
							vertical
							gap={8}
							align="flex-start"
						>
							<span>
								{limitReachedText(
									availability.plan,
									availability.max,
									availability.limit
								)}
							</span>
							<PlanCardButton bucketId={bucketId} />
						</Flex>
					}
				/>
			);
		case 'ownServer':
			return (
				<Alert
					type="info"
					showIcon
					title="Available on your own server"
					description={
						<Flex
							vertical
							gap={8}
							align="flex-start"
						>
							<span>
								It is set up for the whole server, by its super administrator.
								On a server you run yourself, that is you.
							</span>
							<GoButton href={SELF_HOSTING}>Run your own server</GoButton>
						</Flex>
					}
				/>
			);
		case 'askSuperAdmin':
			return (
				<Alert
					type="info"
					showIcon
					title="Needs a super administrator"
					description="It is set up for the whole server. Ask a super administrator of this server to do it."
				/>
			);
		case 'needsRight':
			/*
			 * A project scheduled for deletion is read-only to everyone (frame/can.ts), so asking for a right would
			 * be the wrong advice: restoring it is what opens it again.
			 */
			return scheduled ? (
				<Alert
					type="info"
					showIcon
					title="This project is scheduled for deletion"
					description="Restore it first."
				/>
			) : availability.right === 'changeAddress' && viewer.superAdmin ? (
				/* A super administrator is refused only at the two projects served at the server's root (can.ts). */
				<Alert
					type="info"
					showIcon
					title="This project keeps the server’s own address"
					description="It is served at the server’s root, and moving it would take the console that could move it back with it."
				/>
			) : availability.right === 'changeAddress' ? (
				<Alert
					type="info"
					showIcon
					title="Needs the right to change this project’s address"
					description="An owner of the team that owns this project changes its path or subdomain, and only while the project holds no application, identity provider, provisioning connection or connected service. After that, and for a domain of its own, ask a super administrator."
				/>
			) : (
				<Alert
					type="info"
					showIcon
					title={
						availability.right === 'edit'
							? 'Needs the right to change this project'
							: 'Needs the right to manage this project’s users'
					}
					description="Ask a team owner: only members of the team that owns this project can do this."
				/>
			);
	}
}

/*
 * A drawn hint of the screen the person meets, not a screenshot, with the guide's example names (GUIDE_EXAMPLES): the
 * app is Acme Notes, the company Acme Corp, the agent Claude, the outside service Google; an agent managing FoxAuth
 * itself meets this console instead of the app. The same screens the site draws (MiniScreen.astro), in the console's
 * colours. Decoration, hidden from assistive technology: the lines beside it say the same in words.
 */
function MiniScreen({ kind }: { kind: Exclude<GuidePreview['kind'], 'none'> }) {
	const consoleHost = useInstanceHost();
	const examples = GUIDE_EXAMPLES;
	const host =
		kind === 'adminConsent'
			? consoleHost
			: `auth.${examples.app.toLowerCase().replaceAll(' ', '-')}.app`;
	const deny = <div className="gs-ms-b s">Deny</div>;
	const allow = <div className="gs-ms-b p">Allow</div>;
	const asks = (part: 'agent' | 'cloud', who: string, what: string) => (
		<div className="gs-ms-who">
			<Glyph part={part} />
			<span>
				<b>{who}</b>
				<span className="gs-ms-t">{what}</span>
			</span>
		</div>
	);
	const scopes = (items: string[]) => (
		<ul className="gs-ms-perm">
			{items.map((scope) => (
				<li key={scope}>
					<Glyph strokeWidth={2.5} />
					{scope}
				</li>
			))}
		</ul>
	);
	const body: Record<typeof kind, ReactNode> = {
		signIn: (
			<>
				<div className="gs-ms-h">Sign in</div>
				<div className="gs-ms-f">Email</div>
				<div className="gs-ms-f">Password</div>
				<div className="gs-ms-b p">Sign in</div>
				<div className="gs-ms-or">or</div>
				<div className="gs-ms-b s">Continue with Google</div>
			</>
		),
		signUp: (
			<>
				<div className="gs-ms-h">Create an account</div>
				<div className="gs-ms-f">Email</div>
				<div className="gs-ms-f">Password</div>
				<div className="gs-ms-b p">Create account</div>
				<div className="gs-ms-t gs-ms-center">
					Already have an account? Sign in
				</div>
			</>
		),
		companySignIn: (
			<>
				<div className="gs-ms-h">Sign in</div>
				<div className="gs-ms-b p icon">
					<Glyph
						part="company"
						strokeWidth={2}
					/>
					<span>
						Continue with <b>{examples.company}</b>
					</span>
				</div>
				<div className="gs-ms-or">or</div>
				<div className="gs-ms-f">Email</div>
				<div className="gs-ms-f">Password</div>
			</>
		),
		consent: (
			<>
				<div className="gs-ms-h">An app asks for access</div>
				<div className="gs-ms-t">It will act on your behalf.</div>
				<div className="gs-ms-row">
					{deny}
					{allow}
				</div>
			</>
		),
		agentConsent: (
			<>
				{asks('agent', examples.agent, 'asks to act on your behalf')}
				{scopes(['Read your notes', 'Add new notes'])}
				<div className="gs-ms-row">
					{deny}
					{allow}
				</div>
			</>
		),
		adminConsent: (
			<>
				{asks('agent', examples.agent, 'asks to act as you')}
				{scopes([
					'See your projects and applications',
					'Create and change applications'
				])}
				<div className="gs-ms-row">
					{deny}
					{allow}
				</div>
			</>
		),
		serviceConsent: (
			<>
				{asks('cloud', examples.service, 'Connect your account')}
				<div className="gs-ms-t">
					Your agent can then use it on your behalf, through FoxAuth.
				</div>
				<div className="gs-ms-row">
					<div className="gs-ms-b s">Cancel</div>
					<div className="gs-ms-b p">Connect</div>
				</div>
			</>
		),
		deviceCode: (
			<>
				<div className="gs-ms-who">
					<Glyph part="tv" />
					<span className="gs-ms-t">Type the code from the screen</span>
				</div>
				<div className="gs-ms-code">WDJB-MJHT</div>
				<div className="gs-ms-b p">Next</div>
			</>
		),
		approve: (
			<>
				<div className="gs-ms-who">
					<Glyph part="phone" />
					<span className="gs-ms-h">Approve a request?</span>
				</div>
				<div className="gs-ms-t">Who is asking, and for what.</div>
				<div className="gs-ms-row">
					<div className="gs-ms-b s">Decline</div>
					<div className="gs-ms-b p">Approve</div>
				</div>
			</>
		)
	};
	return (
		<div
			className="gs-ms"
			aria-hidden="true"
		>
			<div className="gs-ms-bar">
				<span className="gs-ms-dots">
					<i />
					<i />
					<i />
				</span>
				<span className="gs-ms-host">{kind === 'approve' ? '' : host}</span>
			</div>
			<div className="gs-ms-in">
				{kind === 'adminConsent' ? (
					<div className="gs-ms-brand">
						<span className="gs-ms-logo fox">
							<Glyph
								part="fox"
								strokeWidth={2}
							/>
						</span>
						<span>FoxAuth administration</span>
					</div>
				) : (
					kind !== 'approve' &&
					kind !== 'deviceCode' && (
						<div className="gs-ms-brand">
							<span className="gs-ms-logo">{examples.app.slice(0, 1)}</span>
							<span>{examples.app}</span>
						</div>
					)
				)}
				{body[kind]}
			</div>
		</div>
	);
}

/* The strip's third frame: the screen and the lines that name what is on it, or a checklist where there is no screen. */
function WhatYouGet({ sees }: { sees: GuidePreview }) {
	if (sees.kind === 'none') {
		return (
			<div className="gs-get">
				<ul className="gs-result">
					{sees.lines.map((line) => (
						<li key={line}>
							<span className="gs-result-dot">
								<Glyph strokeWidth={3} />
							</span>
							<span>{line}</span>
						</li>
					))}
				</ul>
			</div>
		);
	}
	return (
		<div className="gs-get">
			<div className="gs-get-pic">
				<MiniScreen kind={sees.kind} />
			</div>
			<ul className="gs-get-lines">
				{sees.lines.map((line) => (
					<li key={line}>{line}</li>
				))}
			</ul>
		</div>
	);
}

function Bullets({ items }: { items: readonly string[] }) {
	return (
		<ul style={{ margin: 0, paddingInlineStart: 20 }}>
			{items.map((item) => (
				<li key={item}>{item}</li>
			))}
		</ul>
	);
}

function FilledIn({ s }: { s: GuideSituation }) {
	if (!s.preset) return null;
	const preset = presetOf(s.preset);
	if (!preset.expand) return null;
	const dev = preset.devAddress ?? '';
	const e = preset.expand(dev);
	const rows: [string, string[]][] = [
		['Application type', [e.applicationType]],
		['How it gets tokens', e.grantTypes],
		['How it proves who it is', [e.tokenEndpointAuthMethod]],
		['Callback addresses', e.redirectUris],
		['After sign-out', e.postLogoutRedirectUris],
		['Allowed browser origins', e.corsOrigins]
	];
	return (
		<Flex
			vertical
			gap={8}
		>
			<Typography.Title
				level={5}
				style={{ margin: 0 }}
			>
				What gets filled in for you
			</Typography.Title>
			<dl style={{ margin: 0, display: 'grid', gap: 6 }}>
				{rows
					.filter(([, values]) => values.length > 0)
					.map(([label, values]) => (
						<div key={label}>
							<dt>
								<Typography.Text
									type="secondary"
									style={{ fontSize: 12 }}
								>
									{label}
								</Typography.Text>
							</dt>
							<dd style={{ margin: 0, overflowWrap: 'anywhere' }}>
								{values.map((v) => (
									<Typography.Text
										key={v}
										code
									>
										{v}
									</Typography.Text>
								))}
							</dd>
						</div>
					))}
			</dl>
			<Typography.Text type="secondary">
				{dev
					? `The addresses follow your development address, ${dev}. The form lets you change it, and every other field, before anything is created.`
					: 'The form lets you change every field before anything is created.'}
			</Typography.Text>
		</Flex>
	);
}

export function GuideAnswer({
	bucketId,
	situation: s,
	viewer,
	issuer,
	scheduled = false,
	compact = false
}: {
	bucketId: string;
	situation: GuideSituation;
	viewer: GuideViewer;
	issuer: string | null;
	/* The project is scheduled for deletion: read-only to everyone until it is restored. */
	scheduled?: boolean;
	compact?: boolean;
}) {
	const feedback = useFeedback();
	const palette = useDiagramPalette();
	const action = actionFor(bucketId, s, viewer, issuer);
	const copy = () => {
		const text = renderPrompt(s, {
			issuer,
			console: `${window.location.origin}/admin`
		});
		const refused = () => {
			feedback.refused({
				error: 'copy_refused',
				message:
					'The browser did not allow copying. Allow clipboard access and try again.'
			});
		};
		// Absent outside a secure context, whatever the type says.
		try {
			navigator.clipboard.writeText(text).then(() => {
				feedback.done('The prompt for your agent is copied.');
			}, refused);
		} catch {
			refused();
		}
	};
	const persona = personaOf(s);
	const next = s.next ? guideSituation(s.next) : undefined;

	return (
		<Card
			className="guide-scope"
			style={palette}
		>
			<PictureStyles />
			<Flex
				vertical
				gap={20}
			>
				<Flex
					vertical
					gap={8}
				>
					<Flex
						wrap
						gap={8}
						align="center"
					>
						<Tag
							color={persona === 'enterprise' ? 'purple' : 'blue'}
							style={{ marginInlineEnd: 0 }}
						>
							{PERSONA[persona]}
						</Tag>
						<StatusMark
							status={statusOf(action, scheduled)}
							size="md"
						/>
					</Flex>
					<Typography.Title
						level={4}
						style={{ margin: 0 }}
					>
						{s.title}
					</Typography.Title>
					<Typography.Paragraph style={{ margin: 0, maxWidth: 720 }}>
						{s.sentence}
					</Typography.Paragraph>
				</Flex>
				<Strip
					situation={s}
					get={<WhatYouGet sees={s.sees} />}
				/>
				<Action
					bucketId={bucketId}
					action={action}
					viewer={viewer}
					scheduled={scheduled}
				/>
				{next && (
					<Link
						href={`${bucketHref(bucketId, 'guide')}?${next.tab === 'enterprise' ? 'e' : 's'}=${encodeURIComponent(next.id)}`}
						className="gs-next"
					>
						<span className="gs-next-k">Next:</span>
						<span className="gs-next-t">{next.title}</span>
						<span
							aria-hidden="true"
							className="gs-next-arrow"
						>
							→
						</span>
					</Link>
				)}
				<Flex
					vertical
					gap={8}
				>
					<Typography.Title
						level={5}
						style={{ margin: 0 }}
					>
						How it works, step by step
					</Typography.Title>
					<SequenceDiagram
						key={s.id}
						lanes={s.lanes}
						steps={s.steps}
						title={s.title}
					/>
				</Flex>
				{!compact && s.preset && <FilledIn s={s} />}
				{s.goodToKnow.length > 0 && (
					<Flex
						vertical
						gap={8}
					>
						<Typography.Title
							level={5}
							style={{ margin: 0 }}
						>
							Good to know
						</Typography.Title>
						<Bullets items={s.goodToKnow} />
					</Flex>
				)}
				<Flex
					wrap
					gap={12}
					align="center"
					justify="space-between"
				>
					<Button
						icon={<CopyOutlined />}
						onClick={copy}
					>
						Copy prompt for your agent
					</Button>
					<Typography.Text
						type="secondary"
						style={{ fontSize: 12 }}
					>
						Under the hood: {s.protocol}
					</Typography.Text>
				</Flex>
			</Flex>
		</Card>
	);
}
