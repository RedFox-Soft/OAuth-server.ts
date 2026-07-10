export function isHttpsUri(uri: string) {
	return URL.parse(uri)?.protocol === 'https:';
}

export function isWebUri(uri: string) {
	const protocol = URL.parse(uri)?.protocol;
	return protocol === 'https:' || protocol === 'http:';
}
