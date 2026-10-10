/*
 * The rights the server states on a bucket and a project (specs/079 data-model §2), as the console reads
 * them. Each flag answers one question: would the route accept this request from this caller?
 *
 * Read through `bucketCan`/`projectCan`, which answer "yes" for a flag the response does not carry: the
 * server still refuses what it refuses, so a missing flag can only cost a 403 the console used to show
 * anyway, never hide something the operator may do.
 */

export interface BucketCan {
	read: boolean;
	manageUsers: boolean;
	editSettings: boolean;
	edit: boolean;
	readActivity: boolean;
	changeAddress: boolean;
	move: boolean;
	delete: boolean;
}

export interface BucketBlockers {
	usedByProjects: { id: string; name: string }[];
	addressable: boolean;
}

export interface ProjectCan {
	read: boolean;
	edit: boolean;
	delete: boolean;
	manageClients: boolean;
	declareResources: boolean;
	assignBucket: boolean;
	move: boolean;
}

export interface ProjectBlockers {
	hasBucket: boolean;
}

const ALL_BUCKET: BucketCan = {
	read: true,
	manageUsers: true,
	editSettings: true,
	edit: true,
	readActivity: true,
	changeAddress: true,
	move: true,
	delete: true
};

const ALL_PROJECT: ProjectCan = {
	read: true,
	edit: true,
	delete: true,
	manageClients: true,
	declareResources: true,
	assignBucket: true,
	move: true
};

export function bucketCan(
	bucket: { can?: Partial<BucketCan> } | null
): BucketCan {
	return { ...ALL_BUCKET, ...bucket?.can };
}

export function projectCan(
	project: { can?: Partial<ProjectCan> } | null
): ProjectCan {
	return { ...ALL_PROJECT, ...project?.can };
}
