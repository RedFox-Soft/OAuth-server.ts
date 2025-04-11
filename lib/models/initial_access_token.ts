import apply from './mixins/apply.ts';
import hasFormat from './mixins/has_format.ts';
import hasPolicies from './mixins/has_policies.ts';

export default (provider) =>
	class InitialAccessToken extends apply([
		hasPolicies(provider),
		hasFormat(provider, 'InitialAccessToken', provider.BaseToken)
	]) {
		static get IN_PAYLOAD() {
			return super.IN_PAYLOAD.filter((v) => v !== 'clientId');
		}
	};
