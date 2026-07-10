export function encode(input: string, encoding: BufferEncoding = 'utf8') {
	return Buffer.from(input, encoding).toString('base64url');
}

export function encodeBuffer(buf: Buffer<ArrayBuffer>): string {
	return Buffer.prototype.base64urlSlice.call(buf);
}

export function decode(input: string) {
	return Buffer.from(input, 'base64').toString('utf8');
}
