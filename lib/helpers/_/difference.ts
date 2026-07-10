export default <T>(array: T[], values: T[]): T[] =>
	array.filter((value) => values.indexOf(value) === -1);
