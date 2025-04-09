import setAudience from './mixins/set_audience.ts';
import hasFormat from './mixins/has_format.ts';
import isSenderConstrained from './mixins/is_sender_constrained.ts';
import apply from './mixins/apply.ts';

export default (provider) => class ClientCredentials extends apply([
  setAudience,
  isSenderConstrained,
  hasFormat(provider, 'ClientCredentials', provider.BaseToken),
]) {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'aud',
      'extra',
      'scope',
    ];
  }
};
