import { useEffect, useRef, useState, type ReactNode } from 'react';
import {
	Button,
	Card,
	Collapse,
	Flex,
	Radio,
	Table,
	Tabs,
	Tag,
	Typography
} from 'antd';
import {
	DEFAULT_ANSWER,
	GUIDE_QUESTIONS,
	GUIDE_SITUATIONS,
	guideSituation,
	type GuideActor,
	type GuideFlag,
	type GuideSituation,
	type GuideTab
} from '../../../../consts/situation_guide.js';
import {
	guideSelection,
	type GuideViewer
} from '../../../../situation_guide/availability.js';
import { optionPartsOf } from '../../../../situation_guide/options.js';
import type { BucketCan } from '../../frame/can.js';
import { useMe } from '../../frame/me.js';
import { Link, useNavigate, useRoute } from '../../frame/router.js';
import { bucketHref } from '../../frame/routes.js';
import type { BucketSummary, BucketView } from '../bucketView.js';
import { GoButton, GuideAnswer } from './AnswerPanel.js';
import { ActorThumb, StatusMark, Thumb } from './Part.js';
import { PictureStyles } from './Scene.js';
import { DiagramStyles, useDiagramPalette } from './SequenceDiagram.js';
import {
	DOCS_ORIGIN,
	actionFor,
	leavesConsole,
	statusOf,
	type GuideStatus
} from './targets.js';
import { guideViewerOf } from './viewer.js';

/*
 * "What do you need?" (the situation guide): two tabs, your product and your customer's company; on the first, two
 * questions and a row of common tasks, on the second a short list; the answer below rewrites in place. The choice
 * is kept in the address (`?s=` or `?e=`), so a link reopens the same answer. Nothing here creates anything: every
 * button opens a form or a page, and the person submits there.
 */

const CSS = `
.guide-options { display: grid; grid-template-columns: repeat(auto-fill, minmax(min(100%, 220px), 1fr)); gap: 8px; width: 100%; }
.guide-options .ant-radio-wrapper.guide-option { margin: 0; padding: 10px 12px; border: 1px solid var(--gd-line); border-radius: 8px; align-items: flex-start; background: var(--gd-surface); }
.guide-options .ant-radio-wrapper.guide-option:hover { border-color: var(--gd-accent); }
.guide-options .ant-radio-wrapper-checked.guide-option { border-color: var(--gd-accent); background: var(--gd-accent-soft); }
.guide-options .guide-option:has(input:focus-visible) { outline: 2px solid var(--gd-accent); outline-offset: 2px; }
.guide-option .guide-sub { display: block; color: var(--gd-muted); font-size: 12px; }
.guide-option .guide-top { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 4px 6px; margin-bottom: 6px; }
.guide-option .guide-side { display: flex; align-items: center; gap: 10px; }
.guide-chip.ant-btn { display: inline-flex; align-items: center; gap: 8px; padding: 4px 10px 4px 4px; }
.guide-chip .guide-chip-t { display: flex; flex-direction: column; align-items: flex-start; gap: 2px; }
.guide-legend-q { display: flex; align-items: center; gap: 8px; font-weight: 600; font-size: 15px; margin-bottom: 10px; padding: 0; border: 0; }
.guide-legend-q .n { display: grid; place-items: center; width: 22px; height: 22px; border-radius: 999px; background: var(--gd-ink); color: var(--gd-on-ink); font-size: 12px; font-weight: 800; }
.guide-fieldset { border: 0; margin: 0; padding: 0; min-width: 0; }
.guide-short { display: none; }
.guide-sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
.guide-company { border: 2px dashed var(--gd-accent); border-radius: 12px; background: var(--gd-accent-soft); padding: 16px; }
.guide-key { display: inline-block; flex-shrink: 0; width: 28px; height: 18px; border-radius: 5px; border: 1.5px solid var(--gd-line); background: var(--gd-surface); }
.guide-key.fox { border-color: var(--gd-accent); background: var(--gd-accent-soft); }
.guide-key.outside { border-style: dashed; border-color: var(--gd-life); }
.guide-key.proxy { border: 2.5px double var(--gd-ink); }
.guide-key.redirect { height: 0; border: 0; border-top: 2px dashed var(--gd-arrow); border-radius: 0; background: none; }
.guide-key.token { height: 0; border: 0; border-top: 3px solid var(--gd-arrow); border-radius: 0; background: none; }
.guide-key.refusal { height: 0; border: 0; border-top: 2.5px dashed var(--gd-deny); border-radius: 0; background: none; }
@media (max-width: 575px) {
  .guide-long { display: none; }
  .guide-short { display: inline; }
  .guide-options.compact .guide-sub { display: none; }
  .guide-company { padding: 12px; }
}
`;

/* The small picture on each answer's option, read off the answer's own scenes (lib/situation_guide/options.ts). */
const OPTION_PARTS = new Map(
	GUIDE_SITUATIONS.map((s) => [s.id, optionPartsOf(s)])
);

/* What the second question preselects for each answer to the first: its first answer. */
const FIRST_ANSWER = Object.fromEntries(
	GUIDE_QUESTIONS.map((q) => [q.actor, q.answers[0]?.answer ?? ''])
) as Record<GuideActor, string>;

const CHIPS = GUIDE_SITUATIONS.filter((s) => s.tab === 'product' && !s.ask);
/* Company sign-in and SCIM first: they usually come together. */
const ENTERPRISE = [
	...GUIDE_SITUATIONS.filter((s) => s.tab === 'enterprise' && s.first),
	...GUIDE_SITUATIONS.filter((s) => s.tab === 'enterprise' && !s.first)
];

interface Product {
	actor: GuideActor;
	/* The second answer remembered for each first one, so going back and forth keeps what was chosen. */
	answers: Record<GuideActor, string>;
	/* A common task chosen instead of the two questions. */
	chip: string | null;
}

function productAt(product: Product, id: string): Product {
	const s = guideSituation(id);
	if (!s || s.tab !== 'product') return product;
	if (s.ask) {
		return {
			actor: s.ask.actor,
			answers: { ...product.answers, [s.ask.actor]: s.ask.answer },
			chip: null
		};
	}
	return { ...product, chip: id };
}

function productId(product: Product): string {
	return product.chip ?? product.answers[product.actor];
}

const START: Product = {
	actor: 'person',
	answers: FIRST_ANSWER,
	chip: null
};

function initialState(query: URLSearchParams) {
	const picked = guideSelection(query);
	return {
		tab: picked.tab,
		product: productAt(
			START,
			picked.tab === 'product' ? picked.id : DEFAULT_ANSWER.product
		),
		enterprise:
			picked.tab === 'enterprise' ? picked.id : DEFAULT_ANSWER.enterprise
	};
}

/*
 * The address of an answer: the page's own, with `?s=` or `?e=`. Written with a replacing navigation that does not
 * scroll, so a reload or a shared link reopens the answer, Back does not step through every choice, and the router
 * knows the query (a later link to it is then a real change).
 */
function addressOf(tab: GuideTab, id: string): string {
	const url = new URL(window.location.href);
	url.searchParams.delete('s');
	url.searchParams.delete('e');
	url.searchParams.set(tab === 'product' ? 's' : 'e', id);
	return `${url.pathname}${url.search}${url.hash}`;
}

/* On a phone the answer sits below the choices: bring it up when it is out of sight. */
function reveal(el: HTMLElement | null) {
	if (!el || !window.matchMedia('(max-width: 767px)').matches) return;
	if (el.getBoundingClientRect().top < window.innerHeight * 0.6) return;
	const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
	el.scrollIntoView({ behavior: reduced ? 'auto' : 'smooth', block: 'start' });
}

/*
 * An option's words, with its answer's picture and status over them (question 2, the company's list) or the actor's
 * drawing beside them (question 1).
 */
function OptionLabel({
	title,
	sub,
	situationId,
	status,
	actor
}: {
	title: string;
	sub?: string;
	situationId?: string;
	status?: GuideStatus;
	actor?: GuideActor;
}) {
	const words = (
		<span>
			<Typography.Text strong>{title}</Typography.Text>
			{sub && <span className="guide-sub">{sub}</span>}
		</span>
	);
	if (actor) {
		return (
			<span className="guide-side">
				<ActorThumb actor={actor} />
				{words}
			</span>
		);
	}
	return (
		<span>
			{situationId && (
				<span className="guide-top">
					<Thumb parts={OPTION_PARTS.get(situationId) ?? ['fox']} />
					{status && <StatusMark status={status} />}
				</span>
			)}
			{words}
		</span>
	);
}

function Question({
	n,
	legend,
	children
}: {
	n: number;
	legend: string;
	children: ReactNode;
}) {
	return (
		<fieldset className="guide-fieldset">
			<legend className="guide-legend-q">
				<span
					className="n"
					aria-hidden="true"
				>
					{n}
				</span>
				{legend}
			</legend>
			{children}
		</fieldset>
	);
}

function Legend() {
	const items: [string, string][] = [
		[
			'fox',
			'FoxAuth is always the coloured box, and its steps are in the same colour.'
		],
		['', 'A plain box is you, your code or the person.'],
		[
			'outside',
			'A dashed box is a service outside your control, or your customer’s company.'
		],
		[
			'proxy',
			'A box with a double border is your reverse proxy, which every request to your app passes through.'
		],
		[
			'redirect',
			'A long-dashed arrow sends the person’s browser on to another address.'
		],
		['token', 'A thick arrow carries a token.'],
		['refusal', 'A red dashed arrow is a refusal.']
	];
	return (
		<Flex
			vertical
			gap={10}
		>
			{items.map(([kind, text]) => (
				<Flex
					key={text}
					gap={12}
					align="center"
				>
					<span className={`guide-key ${kind}`} />
					<span>{text}</span>
				</Flex>
			))}
			<span>
				Each arrow is numbered. Point at a numbered step in the list, or move to
				it with Tab, to pick out its arrow.
			</span>
		</Flex>
	);
}

export function GuidePage({
	bucket,
	summary,
	can,
	superAdmin,
	features
}: {
	bucket: BucketView;
	summary: BucketSummary | null;
	can: BucketCan;
	superAdmin: boolean;
	features: Record<GuideFlag, boolean> | undefined;
}) {
	const bucketId = bucket._id;
	const palette = useDiagramPalette();
	const { location, query } = useRoute();
	const navigate = useNavigate();
	const writeAddress = (tab: GuideTab, id: string) => {
		void navigate(addressOf(tab, id), { replace: true, scroll: false });
	};
	const [state, setState] = useState(() => initialState(query));
	/*
	 * A link inside the console to another answer of this page arrives as a new query on the same page; it is
	 * applied while rendering, the way React adjusts state to a changed input, rather than in an effect.
	 */
	const [seen, setSeen] = useState(location.search);
	if (location.search !== seen) {
		setSeen(location.search);
		const picked = guideSelection(query);
		setState((current) =>
			picked.tab === 'product'
				? {
						...current,
						tab: 'product',
						product: productAt(current.product, picked.id)
					}
				: { ...current, tab: 'enterprise', enterprise: picked.id }
		);
	}
	const productAnswer = useRef<HTMLDivElement>(null);
	const enterpriseAnswer = useRef<HTMLDivElement>(null);
	/*
	 * The switches (`features`) ride on `me`, which the console reads once and then only when told: read it again
	 * here, so a feature a super administrator switched on since shows as ready without a page reload.
	 */
	const { reload: reloadMe } = useMe();
	useEffect(() => {
		void reloadMe();
	}, [reloadMe]);

	const viewer: GuideViewer = guideViewerOf({
		features,
		superAdmin,
		can,
		summary
	});
	const issuer = bucket.issuer ?? null;
	const scheduled = Boolean(bucket.deletion);
	const statusFor = (s: GuideSituation | undefined) =>
		s ? statusOf(actionFor(bucketId, s, viewer, issuer), scheduled) : undefined;

	const chooseProduct = (next: Product) => {
		setState((current) => ({ ...current, product: next }));
		writeAddress('product', productId(next));
		reveal(productAnswer.current);
	};
	const chooseEnterprise = (id: string) => {
		setState((current) => ({ ...current, enterprise: id }));
		writeAddress('enterprise', id);
		reveal(enterpriseAnswer.current);
	};
	const show = (s: GuideSituation) => {
		if (s.tab === 'product') {
			const next = productAt(state.product, s.id);
			setState((current) => ({ ...current, tab: 'product', product: next }));
		} else {
			setState((current) => ({
				...current,
				tab: 'enterprise',
				enterprise: s.id
			}));
		}
		writeAddress(s.tab, s.id);
		window.scrollTo({ top: 0 });
	};

	const product = state.product;
	const question =
		GUIDE_QUESTIONS.find((q) => q.actor === product.actor) ??
		GUIDE_QUESTIONS[0];
	const productSituation =
		guideSituation(productId(product)) ??
		guideSituation(DEFAULT_ANSWER.product);
	const enterpriseSituation =
		guideSituation(state.enterprise) ??
		guideSituation(DEFAULT_ANSWER.enterprise);

	const productTab = (
		<Flex
			vertical
			gap={24}
		>
			<Question
				n={1}
				legend="Who is acting?"
			>
				<Radio.Group
					className="guide-options compact"
					value={product.actor}
					onChange={(e) => {
						const actor = e.target.value as GuideActor;
						chooseProduct({ ...product, actor, chip: null });
					}}
				>
					{GUIDE_QUESTIONS.map((q) => (
						<Radio
							key={q.actor}
							value={q.actor}
							className="guide-option"
						>
							<OptionLabel
								title={q.title}
								sub={q.sub}
								actor={q.actor}
							/>
						</Radio>
					))}
				</Radio.Group>
			</Question>
			<Question
				n={2}
				legend={question.second}
			>
				<Radio.Group
					className="guide-options"
					value={product.chip ? null : product.answers[product.actor]}
					onChange={(e) => {
						chooseProduct({
							...product,
							answers: {
								...product.answers,
								[product.actor]: e.target.value as string
							},
							chip: null
						});
					}}
				>
					{question.answers.map((a) => (
						<Radio
							key={a.answer}
							value={a.answer}
							className="guide-option"
						>
							<OptionLabel
								title={a.title}
								sub={a.sub}
								situationId={a.answer}
								status={statusFor(guideSituation(a.answer))}
							/>
						</Radio>
					))}
				</Radio.Group>
				{product.actor === 'agent' && (
					<Typography.Paragraph
						type="secondary"
						style={{ margin: '10px 0 0' }}
					>
						Does the agent run on the person’s computer and sign in as them?
						That is the same case as{' '}
						<Typography.Link
							onClick={() => {
								chooseProduct(productAt(product, 'native'));
							}}
						>
							an app on a desktop or in a terminal
						</Typography.Link>
						.
					</Typography.Paragraph>
				)}
			</Question>
			<Flex
				vertical
				gap={10}
			>
				<Typography.Text strong>More common tasks</Typography.Text>
				<Flex
					wrap
					gap={8}
				>
					{CHIPS.map((s) => {
						const status = statusFor(s);
						return (
							<Button
								key={s.id}
								className="guide-chip"
								type={product.chip === s.id ? 'primary' : 'default'}
								ghost={product.chip === s.id}
								aria-pressed={product.chip === s.id}
								onClick={() => {
									chooseProduct(productAt(product, s.id));
								}}
								style={{
									whiteSpace: 'normal',
									height: 'auto',
									textAlign: 'start'
								}}
							>
								<Thumb
									parts={OPTION_PARTS.get(s.id) ?? ['fox']}
									small
								/>
								<span className="guide-chip-t">
									<span>{s.title}</span>
									{status && <StatusMark status={status} />}
								</span>
							</Button>
						);
					})}
				</Flex>
			</Flex>
			<div
				ref={productAnswer}
				style={{ scrollMarginTop: 16 }}
			>
				{productSituation && (
					<GuideAnswer
						bucketId={bucketId}
						situation={productSituation}
						viewer={viewer}
						issuer={issuer}
						scheduled={scheduled}
					/>
				)}
			</div>
		</Flex>
	);

	const enterpriseTab = (
		<Flex
			vertical
			gap={24}
		>
			<div className="guide-company">
				<Flex
					vertical
					gap={12}
				>
					<div>
						<Tag color="purple">Your customer’s company</Tag>
					</div>
					<Typography.Title
						level={4}
						style={{ margin: 0 }}
					>
						When your customer is a company: what their IT department will ask
						for
					</Typography.Title>
					<Typography.Paragraph style={{ margin: 0 }}>
						An ordinary app needs none of this. Pick what the company is asking
						for. Company sign-in and SCIM come first: they usually arrive
						together.
					</Typography.Paragraph>
					<fieldset className="guide-fieldset">
						<legend className="guide-legend-q">
							What is the company asking for?
						</legend>
						<Radio.Group
							className="guide-options"
							value={state.enterprise}
							onChange={(e) => {
								chooseEnterprise(e.target.value as string);
							}}
						>
							{ENTERPRISE.map((s) => (
								<Radio
									key={s.id}
									value={s.id}
									className="guide-option"
								>
									<OptionLabel
										title={s.title}
										sub={
											s.first ? 'Usually together with the other' : undefined
										}
										situationId={s.id}
										status={statusFor(s)}
									/>
								</Radio>
							))}
						</Radio.Group>
					</fieldset>
				</Flex>
			</div>
			<div
				ref={enterpriseAnswer}
				style={{ scrollMarginTop: 16 }}
			>
				{enterpriseSituation && (
					<GuideAnswer
						bucketId={bucketId}
						situation={enterpriseSituation}
						viewer={viewer}
						issuer={issuer}
						scheduled={scheduled}
					/>
				)}
			</div>
		</Flex>
	);

	const fullForm = `${bucketHref(bucketId, 'applications')}?situation=custom`;

	return (
		<div
			className="guide-scope"
			style={palette}
		>
			<DiagramStyles />
			<PictureStyles />
			<style dangerouslySetInnerHTML={{ __html: CSS }} />
			<Tabs
				activeKey={state.tab}
				onChange={(key) => {
					const tab = key as GuideTab;
					setState((current) => ({ ...current, tab }));
					writeAddress(
						tab,
						tab === 'product' ? productId(state.product) : state.enterprise
					);
				}}
				items={[
					{
						key: 'product',
						label: (
							<>
								<span className="guide-long">
									Your product: sign-in for people and agents
								</span>
								<span className="guide-short">Your product</span>
							</>
						),
						children: productTab
					},
					{
						key: 'enterprise',
						label: (
							<>
								<span className="guide-long">
									Your customer is a company (Enterprise)
								</span>
								<span className="guide-short">Enterprise</span>
							</>
						),
						children: enterpriseTab
					}
				]}
			/>
			<Flex
				vertical
				gap={16}
				style={{ marginTop: 24 }}
			>
				<Collapse
					items={[
						{
							key: 'legend',
							label: 'How to read the diagrams',
							children: <Legend />
						}
					]}
				/>
				<Collapse
					items={[
						{
							key: 'all',
							label: `Show all situations (${String(GUIDE_SITUATIONS.length)})`,
							children: (
								<Table<GuideSituation>
									size="small"
									pagination={false}
									rowKey="id"
									dataSource={[...GUIDE_SITUATIONS]}
									columns={[
										{
											key: 'title',
											title: 'Situation',
											render: (_, s) => (
												<Flex
													vertical
													gap={2}
												>
													<span>{s.title}</span>
													<Flex
														wrap
														gap={8}
														align="center"
													>
														<Tag
															color={s.tab === 'enterprise' ? 'purple' : 'blue'}
															style={{ marginInlineEnd: 0 }}
														>
															{s.tab === 'enterprise'
																? 'Enterprise'
																: 'Your product'}
														</Tag>
														<StatusMark
															status={statusOf(
																actionFor(bucketId, s, viewer, issuer),
																scheduled
															)}
														/>
													</Flex>
												</Flex>
											)
										},
										{
											key: 'protocol',
											title: 'Under the hood',
											responsive: ['md'],
											render: (_, s) => (
												<Typography.Text type="secondary">
													{s.protocol}
												</Typography.Text>
											)
										},
										{
											key: 'go',
											title: <span className="guide-sr">Actions</span>,
											render: (_, s) => {
												const action = actionFor(bucketId, s, viewer, issuer);
												return (
													<Flex
														wrap
														gap={6}
													>
														<Button
															size="small"
															onClick={() => {
																show(s);
															}}
														>
															Show
														</Button>
														{action.kind === 'go' &&
															(leavesConsole(action.href) ? (
																<Typography.Link
																	href={action.href}
																	target="_blank"
																	rel="noopener noreferrer"
																>
																	{action.label}
																</Typography.Link>
															) : (
																<Link href={action.href}>{action.label}</Link>
															))}
													</Flex>
												);
											}
										}
									]}
								/>
							)
						}
					]}
				/>
				<Card>
					<Flex
						vertical
						gap={12}
						align="flex-start"
					>
						<Typography.Title
							level={5}
							style={{ margin: 0 }}
						>
							Nothing fits? Configure everything yourself.
						</Typography.Title>
						<Typography.Text>
							For an application, the full form names every field the way the
							protocol does, with nothing preset. Every server setting and what
							it does is in the settings reference.
						</Typography.Text>
						<Flex
							wrap
							gap={8}
						>
							{can.edit && can.manageUsers && (
								<GoButton href={fullForm}>Open the full form</GoButton>
							)}
							<GoButton href={`${DOCS_ORIGIN}/docs/reference/settings/`}>
								Read the settings reference
							</GoButton>
						</Flex>
					</Flex>
				</Card>
			</Flex>
		</div>
	);
}
