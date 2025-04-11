import instance from '../helpers/weak_cache.ts';

import apply from './mixins/apply.ts';
import hasFormat from './mixins/has_format.ts';
import consumable from './mixins/consumable.ts';

export default (provider) =>
	class PushedAuthorizationRequest extends apply([
		consumable,
		hasFormat(
			provider,
			'PushedAuthorizationRequest',
			instance(provider).BaseModel
		)
	]) {
		static get IN_PAYLOAD() {
			return [...super.IN_PAYLOAD, 'request', 'dpopJkt', 'trusted'];
		}
	};
