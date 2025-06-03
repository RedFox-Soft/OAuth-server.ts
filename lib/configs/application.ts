export const ApplicationConfig = {
	/*
	 * pushedAuthorizationRequests
	 *
	 * title: [`RFC9126`](https://www.rfc-editor.org/rfc/rfc9126.html) - OAuth 2.0 Pushed Authorization Requests (`PAR`)
	 *
	 * description: Enables the use of `pushed_authorization_request_endpoint` defined by the Pushed
	 * Authorization Requests RFC.
	 */
	'par.enabled': false,
	/*
	 * allowUnregisteredRedirectUris
	 *
	 * description: Allows unregistered redirect_uri values to be used by authenticated clients using PAR that do not use a `sector_identifier_uri`.
	 */
	'par.allowUnregisteredRedirectUris': false
};

export type ApplicationConfigType = typeof ApplicationConfig;
