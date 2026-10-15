/*
 * The words a tenant is refused with when it writes to the shared root namespace. Its own module
 * because the declaration routes and the declaration-move helper both refuse with it, and the helper must
 * not import a route module.
 */
export const ROOT_DECLARATION_REFUSAL =
	'APIs of a project without an address of its own can be declared only by a super administrator. Give the project an address to declare its APIs yourself.';
