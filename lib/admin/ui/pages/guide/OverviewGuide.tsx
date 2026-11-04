import { useEffect, useState } from 'react';
import { Card, Flex, Radio, Typography } from 'antd';
import {
	GUIDE_QUESTIONS,
	guideSituation,
	type GuideActor,
	type GuideFlag
} from '../../../../consts/situation_guide.js';
import type { BucketCan } from '../../frame/can.js';
import { useMe } from '../../frame/me.js';
import { Link } from '../../frame/router.js';
import { bucketHref } from '../../frame/routes.js';
import type { BucketSummary, BucketView } from '../bucketView.js';
import { GuideAnswer } from './AnswerPanel.js';
import { guideViewerOf } from './viewer.js';

/*
 * What an empty project's Overview shows in place of "No application signs in here yet": the guide's first two
 * questions and a short answer, with a way into the whole guide. It keeps its own choice and writes nothing to the
 * address: the guide page is where a choice is kept.
 */
export function OverviewGuide({
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
	const [actor, setActor] = useState<GuideActor>('person');
	const [answers, setAnswers] = useState<Partial<Record<GuideActor, string>>>(
		{}
	);
	const question =
		GUIDE_QUESTIONS.find((q) => q.actor === actor) ?? GUIDE_QUESTIONS[0];
	const answer = answers[actor] ?? question.answers.at(0)?.answer ?? 'server';
	const situation = guideSituation(answer);
	const viewer = guideViewerOf({ features, superAdmin, can, summary });
	// The switches ride on `me`; read it again, as the guide page does, so a switch saved since shows here.
	const { reload: reloadMe } = useMe();
	useEffect(() => {
		void reloadMe();
	}, [reloadMe]);

	return (
		<Card
			title="What do you need?"
			extra={
				<Link href={bucketHref(bucket._id, 'guide')}>
					See everything the guide covers
				</Link>
			}
		>
			<Flex
				vertical
				gap={16}
			>
				<Typography.Text type="secondary">
					No application signs in here yet. Say what you are building and see
					how it connects.
				</Typography.Text>
				<fieldset style={{ border: 0, margin: 0, padding: 0, minWidth: 0 }}>
					<legend style={{ fontWeight: 600, padding: 0, marginBottom: 8 }}>
						Who is acting?
					</legend>
					<Radio.Group
						optionType="button"
						value={actor}
						onChange={(e) => {
							setActor(e.target.value as GuideActor);
						}}
						options={GUIDE_QUESTIONS.map((q) => ({
							value: q.actor,
							label: q.title
						}))}
					/>
				</fieldset>
				<fieldset style={{ border: 0, margin: 0, padding: 0, minWidth: 0 }}>
					<legend style={{ fontWeight: 600, padding: 0, marginBottom: 8 }}>
						{question.second}
					</legend>
					<Radio.Group
						optionType="button"
						value={answer}
						onChange={(e) => {
							setAnswers((current) => ({
								...current,
								[actor]: e.target.value as string
							}));
						}}
						options={question.answers.map((a) => ({
							value: a.answer,
							label: a.title
						}))}
					/>
				</fieldset>
				{situation && (
					<GuideAnswer
						bucketId={bucket._id}
						situation={situation}
						viewer={viewer}
						issuer={bucket.issuer ?? null}
						scheduled={Boolean(bucket.deletion)}
						compact
					/>
				)}
			</Flex>
		</Card>
	);
}
