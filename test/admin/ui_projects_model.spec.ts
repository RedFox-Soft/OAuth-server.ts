import { describe, it, expect } from 'bun:test';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { assignableBuckets } from 'lib/admin/ui/projects/model.ts';

const bucket = (id: string, ownerGroupId: string) =>
	({ _id: id, name: id, ownerGroupId }) as Parameters<
		typeof assignableBuckets
	>[0][number];

const project = { ownerGroupId: 'team-a' };

/**
 * @proves An administrator choosing a project's user bucket is offered only the buckets that can
 * actually be assigned, so no choice on the screen answers a refusal.
 */
describe('the buckets a project may be pointed at', () => {
	it('offers a bucket that shares the project owning group', () => {
		const offered = assignableBuckets(
			[bucket('ours', 'team-a'), bucket('also-ours', 'team-a')],
			project
		);

		expect(offered.map((b) => b._id)).toEqual(['ours', 'also-ours']);
	});

	/*
	 * The reported defect. The bucket endpoint hands a super administrator every bucket on the
	 * instance, so the default one — which no group owns — was listed and then refused on save.
	 */
	it('withholds the default bucket, which no group owns', () => {
		const offered = assignableBuckets(
			[bucket('ours', 'team-a'), bucket('redfox', UNASSIGNED_GROUP_ID)],
			project
		);

		expect(offered.map((b) => b._id)).toEqual(['ours']);
	});

	it('withholds a bucket another group owns', () => {
		const offered = assignableBuckets(
			[bucket('theirs', 'team-b'), bucket('ours', 'team-a')],
			project
		);

		expect(offered.map((b) => b._id)).toEqual(['ours']);
	});
});
