import { customAlphabet } from 'nanoid';

/*
 * The address name a project is given on a plan without a custom slug (specs/102): eight random lowercase letters
 * and digits. Random rather than derived from the project's name, so the issuer URL does not carry the tenant's
 * name; 36^8 values make a second draw rare and a sixth one a fault.
 *
 * In a module of its own so the draw can be made to repeat a refused name in a spec: what is proven there is that
 * a drawn name meets every rule a named one does, which a random draw almost never puts to the test.
 */
const draw = customAlphabet('0123456789abcdefghijklmnopqrstuvwxyz', 8);

export const SLUG_DRAWS = 5;

export function drawSlug(): string {
	return draw();
}
