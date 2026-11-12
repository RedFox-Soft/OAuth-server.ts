import type { Address } from '../behind_proxy/net.js';

/*
 * A narrow reader of MaxMind DB 2.0 (https://maxmind.github.io/MaxMind-DB/), for FoxTrust's snapshot (specs/129
 * research R5). Written for FoxAuth with FoxTrust's own reader (same owner) as the reference.
 *
 * Narrow on purpose: it reads the search tree (record sizes 24, 28 and 32) and only the data types FoxTrust's
 * records use. And it never throws. The file is signed, but a reader that could be made to throw would turn one
 * malformed record into an error on a person's request; here every read is bounds-checked, pointers are followed to
 * a fixed depth, and anything outside that is UNREADABLE, which the caller turns into "unknown for this address"
 * (FR-008).
 */

export const UNREADABLE: unique symbol = Symbol('unreadable');
export type Unreadable = typeof UNREADABLE;

export type MmdbValue =
	| string
	| number
	| boolean
	| MmdbValue[]
	| { [key: string]: MmdbValue | undefined };

export interface MmdbMetadata {
	readonly nodeCount: number;
	readonly recordSize: 24 | 28 | 32;
	readonly ipVersion: 4 | 6;
	readonly databaseType: string;
	readonly binaryFormatMajorVersion: number;
	readonly buildEpoch: number;
}

export interface MmdbReader {
	readonly metadata: MmdbMetadata;
	/* The data offset of the record for `address`, null when the tree holds no data for it, or UNREADABLE. */
	lookup(address: Address): number | null | Unreadable;
	decodeAt(offset: number): MmdbValue | Unreadable;
	/* Data leaves of the tree, counted once when the file is opened; for the status card only. */
	readonly leaves: number;
}

const MARKER = Uint8Array.from([
	0xab, 0xcd, 0xef, 0x4d, 0x61, 0x78, 0x4d, 0x69, 0x6e, 0x64, 0x2e, 0x63, 0x6f,
	0x6d
]);
const METADATA_WINDOW = 128 * 1024;
const MAX_POINTER_DEPTH = 8;
const MAX_NESTING = 16;
const MAX_LEAVES_COUNTED = 50_000_000;
const WORD = 0xffffffffn;

class Malformed extends Error {}

function findMarker(bytes: Uint8Array): number {
	const lowest = Math.max(0, bytes.length - METADATA_WINDOW);
	for (let i = bytes.length - MARKER.length; i >= lowest; i--) {
		let match = true;
		for (let j = 0; j < MARKER.length; j++) {
			if (bytes[i + j] !== MARKER[j]) {
				match = false;
				break;
			}
		}
		if (match) return i;
	}
	return -1;
}

const decoder = new TextDecoder('utf-8', { fatal: true });

/* The data section decoder, over `bytes` from `base` to `end`. Pointers are offsets from `base`. */
class Decoder {
	constructor(
		private readonly bytes: Uint8Array,
		private readonly view: DataView,
		private readonly base: number,
		private readonly end: number
	) {}

	private byte(at: number): number {
		if (at < this.base || at >= this.end) throw new Malformed();
		return this.bytes[at];
	}

	private uint(at: number, size: number): number {
		if (size > 4) {
			/* uint64 and uint128 do not occur in these records; reading them exactly would need a bigint. */
			throw new Malformed();
		}
		let value = 0;
		for (let i = 0; i < size; i++) value = value * 256 + this.byte(at + i);
		return value;
	}

	decode(offset: number): MmdbValue {
		return this.read(this.base + offset, 0, 0).value;
	}

	private read(
		at: number,
		pointers: number,
		nesting: number
	): { value: MmdbValue; next: number } {
		if (nesting > MAX_NESTING) throw new Malformed();
		const control = this.byte(at);
		let cursor = at + 1;
		let type = control >> 5;
		if (type === 1) {
			if (pointers >= MAX_POINTER_DEPTH) throw new Malformed();
			const sizeBits = (control >> 3) & 0x3;
			const low = control & 0x7;
			let target: number;
			if (sizeBits === 0) target = (low << 8) | this.byte(cursor);
			else if (sizeBits === 1) {
				target = ((low << 16) | this.uint(cursor, 2)) + 2048;
			} else if (sizeBits === 2) {
				target = low * 0x1000000 + this.uint(cursor, 3) + 526336;
			} else target = this.uint(cursor, 4);
			cursor += sizeBits + 1;
			const resolved = this.read(this.base + target, pointers + 1, nesting);
			return { value: resolved.value, next: cursor };
		}
		if (type === 0) {
			type = 7 + this.byte(cursor);
			cursor += 1;
		}
		let size = control & 0x1f;
		if (size === 29) {
			size = 29 + this.byte(cursor);
			cursor += 1;
		} else if (size === 30) {
			size = 285 + this.uint(cursor, 2);
			cursor += 2;
		} else if (size === 31) {
			size = 65821 + this.uint(cursor, 3);
			cursor += 3;
		}
		switch (type) {
			case 2: {
				if (cursor + size > this.end) throw new Malformed();
				let text: string;
				try {
					text = decoder.decode(this.bytes.subarray(cursor, cursor + size));
				} catch {
					throw new Malformed();
				}
				return { value: text, next: cursor + size };
			}
			case 3:
				if (size !== 8 || cursor + 8 > this.end) throw new Malformed();
				return { value: this.view.getFloat64(cursor), next: cursor + 8 };
			case 5:
			case 6:
				if (size > (type === 5 ? 2 : 4)) throw new Malformed();
				return { value: this.uint(cursor, size), next: cursor + size };
			case 9:
				if (size > 4) throw new Malformed();
				return { value: this.uint(cursor, size), next: cursor + size };
			case 7: {
				const out: { [key: string]: MmdbValue } = {};
				let next = cursor;
				for (let i = 0; i < size; i++) {
					const key = this.read(next, pointers, nesting + 1);
					if (typeof key.value !== 'string') throw new Malformed();
					const value = this.read(key.next, pointers, nesting + 1);
					out[key.value] = value.value;
					next = value.next;
				}
				return { value: out, next };
			}
			case 11: {
				const out: MmdbValue[] = [];
				let next = cursor;
				for (let i = 0; i < size; i++) {
					const item = this.read(next, pointers, nesting + 1);
					out.push(item.value);
					next = item.next;
				}
				return { value: out, next };
			}
			case 14:
				if (size > 1) throw new Malformed();
				return { value: size === 1, next: cursor };
			default:
				throw new Malformed();
		}
	}
}

function metadataOf(value: MmdbValue): MmdbMetadata | null {
	if (typeof value !== 'object' || Array.isArray(value)) return null;
	const nodeCount = value.node_count;
	const recordSize = value.record_size;
	const ipVersion = value.ip_version;
	const databaseType = value.database_type;
	const major = value.binary_format_major_version;
	const buildEpoch = value.build_epoch ?? 0;
	if (
		typeof nodeCount !== 'number' ||
		!Number.isInteger(nodeCount) ||
		nodeCount <= 0 ||
		(recordSize !== 24 && recordSize !== 28 && recordSize !== 32) ||
		(ipVersion !== 4 && ipVersion !== 6) ||
		typeof databaseType !== 'string' ||
		typeof major !== 'number' ||
		typeof buildEpoch !== 'number'
	) {
		return null;
	}
	return {
		nodeCount,
		recordSize,
		ipVersion,
		databaseType,
		binaryFormatMajorVersion: major,
		buildEpoch
	};
}

/* Opens a file, or null when it is no MaxMind DB this reader can use. Reads the bytes in place; never copies them. */
export function openMmdb(bytes: Uint8Array): MmdbReader | null {
	const marker = findMarker(bytes);
	if (marker < 0) return null;
	const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
	const metaStart = marker + MARKER.length;
	let metadata: MmdbMetadata | null;
	try {
		metadata = metadataOf(
			new Decoder(bytes, view, metaStart, bytes.length).decode(0)
		);
	} catch {
		return null;
	}
	if (!metadata) return null;
	const { nodeCount, recordSize } = metadata;
	const nodeBytes = (recordSize * 2) / 8;
	const treeSize = nodeCount * nodeBytes;
	const dataStart = treeSize + 16;
	if (dataStart > marker) return null;
	const data = new Decoder(bytes, view, dataStart, marker);
	const dataSize = marker - dataStart;

	const record = (node: number, bit: number): number => {
		const at = node * nodeBytes;
		if (recordSize === 24) {
			const b = at + bit * 3;
			return (bytes[b] << 16) | (bytes[b + 1] << 8) | bytes[b + 2];
		}
		if (recordSize === 28) {
			const middle = bytes[at + 3];
			if (bit === 0) {
				return (
					((middle & 0xf0) >>> 4) * 0x1000000 +
					((bytes[at] << 16) | (bytes[at + 1] << 8) | bytes[at + 2])
				);
			}
			return (
				(middle & 0x0f) * 0x1000000 +
				((bytes[at + 4] << 16) | (bytes[at + 5] << 8) | bytes[at + 6])
			);
		}
		return view.getUint32(at + bit * 4);
	};

	/* Where IPv4 starts in an IPv6 tree: 96 zero bits down from the root. */
	let ipv4Start = 0;
	if (metadata.ipVersion === 6) {
		let node = 0;
		for (let i = 0; i < 96 && node < nodeCount; i++) node = record(node, 0);
		ipv4Start = node;
	}

	const resolve = (node: number): number | null | Unreadable => {
		if (node === nodeCount) return null;
		if (node < nodeCount) return UNREADABLE;
		const offset = node - nodeCount - 16;
		return offset >= 0 && offset < dataSize ? offset : UNREADABLE;
	};

	const lookup = (address: Address): number | null | Unreadable => {
		let node: number;
		let bits: number;
		const value = address.value;
		if (address.version === 4) {
			node = ipv4Start;
			bits = 32;
		} else {
			if (metadata.ipVersion === 4) return null;
			node = 0;
			bits = 128;
		}
		/*
		 * The address as 32-bit words, read once: a bigint shift per bit would allocate 128 bigints for every IPv6
		 * lookup, and every proxy check with a network facts condition makes one.
		 */
		const words =
			bits === 32
				? [Number(value & WORD)]
				: [
						Number((value >> 96n) & WORD),
						Number((value >> 64n) & WORD),
						Number((value >> 32n) & WORD),
						Number(value & WORD)
					];
		for (let bit = 0; bit < bits && node < nodeCount; bit++) {
			const word = words[bit >>> 5] ?? 0;
			node = record(node, (word >>> (31 - (bit & 31))) & 1);
		}
		return node < nodeCount ? UNREADABLE : resolve(node);
	};

	/* Counts data leaves by walking the tree once, iteratively, with a ceiling so a hostile tree cannot spin. */
	let leaves = 0;
	const stack: number[] = [0];
	let visited = 0;
	while (stack.length > 0 && visited < MAX_LEAVES_COUNTED) {
		const node = stack.pop();
		if (node === undefined) break;
		visited += 1;
		for (let bit = 0; bit < 2; bit++) {
			const next = record(node, bit);
			if (next < nodeCount) {
				if (next > node) stack.push(next);
			} else if (next > nodeCount) leaves += 1;
		}
	}

	return {
		metadata,
		leaves,
		lookup,
		decodeAt(offset: number): MmdbValue | Unreadable {
			try {
				return data.decode(offset);
			} catch {
				return UNREADABLE;
			}
		}
	};
}
