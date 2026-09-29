/*
 * The words a tenant is refused with when it writes to the shared root namespace. Its own module
 * because the declaration routes and the project-move helper both refuse with it, and the helper must
 * not import a route module.
 */
export const ROOT_DECLARATION_REFUSAL =
	'Resources for a project without a bucket of its own can be declared only by a super administrator. Give the project an addressable bucket to declare its resources yourself.';
