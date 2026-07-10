const SET_BOLD_YELLOW_TEXT = '\x1b[33;1m';
const SET_BOLD_RED_TEXT = '\x1b[31;1m';
const RESET_ALL_ATTRIBUTES = '\x1b[0m';

function colorizeStdout(str: string) {
	if (process.stdout.isTTY) {
		return `${SET_BOLD_YELLOW_TEXT}${str}${RESET_ALL_ATTRIBUTES}`;
	}
	return str;
}

function colorizeStderr(str: string) {
	if (process.stderr.isTTY) {
		return `${SET_BOLD_RED_TEXT}${str}${RESET_ALL_ATTRIBUTES}`;
	}
	return str;
}

export function info(str: string) {
	console.info(colorizeStdout(`oidc-provider NOTICE: ${str}`));
}

export function warn(str: string) {
	console.warn(colorizeStderr(`oidc-provider WARNING: ${str}`));
}
