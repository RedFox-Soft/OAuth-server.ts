import apply from './mixins/apply.ts';
import consumable from './mixins/consumable.ts';
import hasFormat from './mixins/has_format.ts';
import hasGrantId from './mixins/has_grant_id.ts';
import isSessionBound from './mixins/is_session_bound.ts';
import storesAuth from './mixins/stores_auth.ts';

export default (provider) => class BackchannelAuthenticationRequest extends apply([
  consumable,
  hasGrantId,
  isSessionBound(provider),
  storesAuth,
  hasFormat(provider, 'BackchannelAuthenticationRequest', provider.BaseToken),
]) {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'error',
      'errorDescription',
      'params',
    ];
  }
};
