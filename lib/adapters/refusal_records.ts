/*
 * One record per person per hold generation of a connection: the same person refused again in the same
 * generation is the same record, and a release, which moves the generation on, starts every person afresh.
 */
export function refusalId(
	connectionId: string,
	epoch: number,
	userId: string
): string {
	return `${connectionId}:${epoch}:${userId}`;
}
