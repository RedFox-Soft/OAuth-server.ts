// The shared OIDC claim set used across the test suite. No longer a provider setup object —
// there is no per-instance provider configuration. bootstrap() merges `claims` onto
// ApplicationConfig for every spec that does not declare its own, which keeps these test-only
// claims out of the production discovery document.
export default () => ({
	claims: {
		address: {
			address: null
		},
		email: {
			email: null,
			email_verified: null
		},
		phone: {
			phone_number: null,
			phone_number_verified: null
		},
		profile: {
			birthdate: null,
			family_name: null,
			gender: null,
			given_name: null,
			locale: null,
			middle_name: null,
			name: null,
			nickname: null,
			picture: null,
			preferred_username: null,
			profile: null,
			updated_at: null,
			website: null,
			zoneinfo: null
		}
	}
});
