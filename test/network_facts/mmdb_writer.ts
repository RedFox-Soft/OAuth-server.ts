/*
 * A test-only MaxMind DB 2.0 writer, after FoxTrust's own (C:/repo/foxtrust/src/mmdb/writer.ts), so specs can build
 * small snapshots at run time instead of committing binary files. An IPv6 tree with IPv4 at ::/96, the data types
 * FoxTrust's records use, a repeated record written once and reached by pointer, and a way to break a file on purpose.
 */

export type WriterValue =
	string | number | boolean | WriterValue[] | { [key: string]: WriterValue };

export interface Entry {
	/* `a.b.c.d/len` or an IPv6 CIDR. */
	readonly cidr: string;
	readonly value: WriterValue;
}

export interface WriterOptions {
	readonly recordSize?: 24 | 28 | 32;
	readonly databaseType?: string;
	readonly buildEpoch?: number;
	readonly majorVersion?: number;
	/* Keys whose numbers are written as doubles, as FoxTrust writes `risk`. */
	readonly doubleKeys?: readonly string[];
}

const textEncoder = new TextEncoder();

function parseCidr(cidr: string): { value: bigint; bits: number } {
	const [text, lengthText] = cidr.split('/');
	const length = Number(lengthText);
	if (text.includes('.')) {
		const parts = text.split('.').map(Number);
		const v4 = parts.reduce((acc, part) => (acc << 8n) | BigInt(part), 0n);
		return { value: v4, bits: 96 + length };
	}
	const halves = text.split('::');
	const head = halves[0] ? halves[0].split(':') : [];
	const tail = halves.length > 1 && halves[1] ? halves[1].split(':') : [];
	const groups = [
		...head,
		...Array<string>(8 - head.length - tail.length).fill('0'),
		...tail
	];
	const value = groups.reduce(
		(acc, group) => (acc << 16n) | BigInt(parseInt(group, 16)),
		0n
	);
	return { value, bits: length };
}

type Child = { node: TrieNode } | { data: number } | null;
interface TrieNode {
	children: [Child, Child];
}

class Encoder {
	readonly chunks: number[] = [];
	constructor(private readonly doubleKeys: ReadonlySet<string>) {}

	private control(type: number, size: number): void {
		const extended = type > 7;
		const first = (extended ? 0 : type) << 5;
		const bytes: number[] = [];
		let code: number;
		if (size < 29) code = size;
		else if (size < 285) {
			code = 29;
			bytes.push(size - 29);
		} else if (size < 65821) {
			code = 30;
			const rest = size - 285;
			bytes.push(rest >> 8, rest & 255);
		} else {
			code = 31;
			const rest = size - 65821;
			bytes.push((rest >> 16) & 255, (rest >> 8) & 255, rest & 255);
		}
		this.chunks.push(first | code);
		if (extended) this.chunks.push(type - 7);
		this.chunks.push(...bytes);
	}

	value(value: WriterValue, key?: string): void {
		if (typeof value === 'string') {
			const bytes = textEncoder.encode(value);
			this.control(2, bytes.length);
			this.chunks.push(...bytes);
		} else if (typeof value === 'boolean') {
			this.control(14, value ? 1 : 0);
		} else if (typeof value === 'number') {
			if (
				(key !== undefined && this.doubleKeys.has(key)) ||
				!Number.isInteger(value)
			) {
				const buffer = new DataView(new ArrayBuffer(8));
				buffer.setFloat64(0, value);
				this.control(3, 8);
				for (let i = 0; i < 8; i++) this.chunks.push(buffer.getUint8(i));
			} else {
				const bytes: number[] = [];
				let rest = value;
				while (rest > 0) {
					bytes.unshift(rest & 255);
					rest = Math.floor(rest / 256);
				}
				this.control(6, bytes.length);
				this.chunks.push(...bytes);
			}
		} else if (Array.isArray(value)) {
			this.control(11, value.length);
			for (const item of value) this.value(item);
		} else {
			const entries = Object.entries(value);
			this.control(7, entries.length);
			for (const [k, v] of entries) {
				this.value(k);
				this.value(v, k);
			}
		}
	}

	pointer(offset: number): void {
		/* Always the 32-bit form: simple, and every form decodes the same. */
		this.chunks.push(
			0b00111000,
			...[24, 16, 8, 0].map((s) => (offset >>> s) & 255)
		);
	}
}

export function writeMmdb(
	entries: readonly Entry[],
	options: WriterOptions = {}
): Uint8Array<ArrayBuffer> {
	const recordSize = options.recordSize ?? 24;
	const doubleKeys = new Set(options.doubleKeys ?? ['risk', 'contribution']);

	/* Data section: each distinct value once; a second copy of a record is a pointer to the first. */
	const data = new Encoder(doubleKeys);
	const offsets = new Map<string, number>();
	const dataOffsetOf = (value: WriterValue): number => {
		const key = JSON.stringify(value);
		const known = offsets.get(key);
		if (known !== undefined) return known;
		const at = data.chunks.length;
		data.value(value);
		offsets.set(key, at);
		return at;
	};

	const root: TrieNode = { children: [null, null] };
	for (const entry of entries) {
		const { value, bits } = parseCidr(entry.cidr);
		const at = dataOffsetOf(entry.value);
		let node = root;
		for (let depth = 0; depth < bits; depth++) {
			const bit = Number((value >> BigInt(127 - depth)) & 1n);
			if (depth === bits - 1) {
				node.children[bit] = { data: at };
				break;
			}
			const child = node.children[bit];
			if (child && 'node' in child) {
				node = child.node;
				continue;
			}
			const next: TrieNode = {
				children: child && 'data' in child ? [child, child] : [null, null]
			};
			node.children[bit] = { node: next };
			node = next;
		}
	}

	const order: TrieNode[] = [];
	const index = new Map<TrieNode, number>();
	const queue: TrieNode[] = [root];
	for (let next = queue.shift(); next !== undefined; next = queue.shift()) {
		const node = next;
		index.set(node, order.length);
		order.push(node);
		for (const child of node.children) {
			if (child && 'node' in child) queue.push(child.node);
		}
	}
	const nodeCount = order.length;
	const nodeBytes = (recordSize * 2) / 8;
	const tree = new Uint8Array(nodeCount * nodeBytes);
	const recordOf = (child: Child): number => {
		if (child === null) return nodeCount;
		if ('node' in child) return index.get(child.node) ?? nodeCount;
		return nodeCount + 16 + child.data;
	};
	order.forEach((node, i) => {
		const left = recordOf(node.children[0]);
		const right = recordOf(node.children[1]);
		const at = i * nodeBytes;
		if (recordSize === 24) {
			tree.set([left >> 16, (left >> 8) & 255, left & 255], at);
			tree.set([right >> 16, (right >> 8) & 255, right & 255], at + 3);
		} else if (recordSize === 28) {
			tree.set([(left >> 16) & 255, (left >> 8) & 255, left & 255], at);
			tree[at + 3] = (((left >>> 24) & 0x0f) << 4) | ((right >>> 24) & 0x0f);
			tree.set([(right >> 16) & 255, (right >> 8) & 255, right & 255], at + 4);
		} else {
			const view = new DataView(tree.buffer);
			view.setUint32(at, left);
			view.setUint32(at + 4, right);
		}
	});

	const metadata = new Encoder(new Set());
	metadata.value({
		node_count: nodeCount,
		record_size: recordSize,
		ip_version: 6,
		database_type: options.databaseType ?? 'FoxTrust-Customer-Verdict',
		languages: ['en'],
		binary_format_major_version: options.majorVersion ?? 2,
		binary_format_minor_version: 0,
		build_epoch: options.buildEpoch ?? 1_794_000_000,
		description: { en: 'test snapshot' }
	});
	const marker = [0xab, 0xcd, 0xef, ...textEncoder.encode('MaxMind.com')];
	const out = new Uint8Array(
		tree.length +
			16 +
			data.chunks.length +
			marker.length +
			metadata.chunks.length
	);
	let offset = 0;
	out.set(tree, offset);
	offset += tree.length + 16;
	out.set(data.chunks, offset);
	offset += data.chunks.length;
	out.set(marker, offset);
	offset += marker.length;
	out.set(metadata.chunks, offset);
	return out;
}

/*
 * Breaks a file the way a test asks: `tree` points the first record past the data section, `record` replaces the
 * first record's bytes with an unknown type, `truncate` cuts the data section short.
 */
export function broken(
	bytes: Uint8Array<ArrayBuffer>,
	how: 'record' | 'truncate'
): Uint8Array<ArrayBuffer> {
	const out = new Uint8Array(bytes);
	const marker = findMarker(out);
	if (how === 'truncate') {
		const metadata = out.slice(marker);
		const cut = new Uint8Array(marker - 4 + metadata.length);
		cut.set(out.subarray(0, marker - 4));
		cut.set(metadata, marker - 4);
		return cut;
	}
	const nodeCount = readNodeCount(out);
	const dataStart = nodeCount * 6 + 16;
	/* Type 4 (bytes) is not a type these records use. */
	out[dataStart] = 0b10000001;
	return out;
}

function findMarker(bytes: Uint8Array): number {
	const marker = textEncoder.encode('MaxMind.com');
	for (let i = bytes.length - marker.length; i >= 0; i--) {
		if (marker.every((b, j) => bytes[i + j] === b)) return i - 3;
	}
	return -1;
}

/* For 24-bit files only, as `broken` is used: the metadata's node_count, found by reading back what writeMmdb wrote. */
function readNodeCount(bytes: Uint8Array): number {
	const key = textEncoder.encode('node_count');
	for (let i = 0; i < bytes.length - key.length; i++) {
		if (key.every((b, j) => bytes[i + j] === b)) {
			const control = bytes[i + key.length];
			const size = control & 0x1f;
			let value = 0;
			for (let j = 0; j < size; j++)
				value = value * 256 + bytes[i + key.length + 1 + j];
			return value;
		}
	}
	return 0;
}
