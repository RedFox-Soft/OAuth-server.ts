import apply from './mixins/apply.ts';
import hasFormat from './mixins/has_format.ts';
import hasPolicies from './mixins/has_policies.ts';

export default (provider) => class RegistrationAccessToken extends apply([
  hasPolicies(provider),
  hasFormat(provider, 'RegistrationAccessToken', provider.BaseToken),
]) {};
