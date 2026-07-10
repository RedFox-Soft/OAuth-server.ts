const map = new WeakMap();

export function get(ctx: object) {
	return map.get(ctx);
}

export function set(ctx: object, value: unknown) {
	return map.set(ctx, value);
}

export default get;
