/* eslint-disable no-new */

import { expect } from 'chai';

import provider from '../../lib/index.ts';

describe('Provider configuration', () => {
	describe('clients', () => {
		it('may contain static clients when these have at least the client_id', () => {
			expect(() => {
				new provider('http://localhost:3000', {
					clients: [null]
				});
			})
				.to.throw(Error)
				.with.property(
					'error_description',
					'client_id is mandatory property for statically configured clients'
				);
			expect(() => {
				new provider('http://localhost:3000', {
					clients: [{}]
				});
			})
				.to.throw(Error)
				.with.property(
					'error_description',
					'client_id is mandatory property for statically configured clients'
				);
		});
		it('client_id must be unique amongst the static clients', () => {
			expect(() => {
				new provider('http://localhost:3000', {
					clients: [{ client_id: 'foo' }, { client_id: 'foo' }]
				});
			})
				.to.throw(Error)
				.with.property(
					'error_description',
					'client_id must be unique amongst statically configured clients'
				);
		});
	});

	describe('acrValues', () => {
		it('only accepts arrays and sets', () => {
			new provider('http://localhost:3000', {
				acrValues: ['bronze', 'silver']
			});
			new provider('http://localhost:3000', {
				acrValues: new Set(['bronze', 'silver'])
			});
			expect(() => {
				new provider('http://localhost:3000', { acrValues: { bronze: true } });
			}).to.throw('acrValues must be an Array or Set');
		});
	});

	describe('subjectTypes', () => {
		it('only accepts arrays and sets', () => {
			new provider('http://localhost:3000', { subjectTypes: ['public'] });
			new provider('http://localhost:3000', {
				subjectTypes: new Set(['public'])
			});
			expect(() => {
				new provider('http://localhost:3000', {
					subjectTypes: { bronze: true }
				});
			}).to.throw('subjectTypes must be an Array or Set');
		});
	});

	describe('scopes', () => {
		it('only accepts arrays and sets', () => {
			new provider('http://localhost:3000', { scopes: ['foo', 'bar'] });
			new provider('http://localhost:3000', {
				scopes: new Set(['foo', 'bar'])
			});
			expect(() => {
				new provider('http://localhost:3000', { scopes: { foo: true } });
			}).to.throw('scopes must be an Array or Set');
		});
	});

	describe('ttl', () => {
		it('checks the values are positive safe integers or functions', () => {
			let throws = [
				() => {
					new provider('http://localhost:3000', { ttl: { default: 0 } });
				},
				() => {
					new provider('http://localhost:3000', {
						ttl: { default: Number.MAX_SAFE_INTEGER + 1 }
					});
				},
				() => {
					new provider('http://localhost:3000', { ttl: { default: -1 } });
				},
				() => {
					new provider('http://localhost:3000', { ttl: { default: Infinity } });
				},
				() => {
					new provider('http://localhost:3000', { ttl: { default: '1' } });
				},
				() => {
					new provider('http://localhost:3000', {
						ttl: {
							async default() {
								return 600;
							}
						}
					});
				},
				() => {
					new provider('http://localhost:3000', {
						ttl: {
							*default() {
								yield 600;
							}
						}
					});
				}
			];

			throws.forEach((fn) => {
				expect(fn).to.throw(
					'ttl.default must be a positive integer or a regular function returning one'
				);
			});

			throws = [
				() => {
					new provider('http://localhost:3000', { ttl: { AccessToken: 0 } });
				},
				() => {
					new provider('http://localhost:3000', {
						ttl: { AccessToken: Number.MAX_SAFE_INTEGER + 1 }
					});
				},
				() => {
					new provider('http://localhost:3000', { ttl: { AccessToken: -1 } });
				},
				() => {
					new provider('http://localhost:3000', {
						ttl: { AccessToken: Infinity }
					});
				},
				() => {
					new provider('http://localhost:3000', { ttl: { AccessToken: '1' } });
				},
				() => {
					new provider('http://localhost:3000', {
						ttl: {
							async AccessToken() {
								return 600;
							}
						}
					});
				},
				() => {
					new provider('http://localhost:3000', {
						ttl: {
							*AccessToken() {
								yield 600;
							}
						}
					});
				}
			];

			throws.forEach((fn) => {
				expect(fn).to.throw(
					'ttl.AccessToken must be a positive integer or a regular function returning one'
				);
			});

			let okay = [
				() => {
					new provider('http://localhost:3000', { ttl: { default: 1 } });
				},
				() => {
					new provider('http://localhost:3000', {
						ttl: { default: Number.MAX_SAFE_INTEGER }
					});
				},
				() => {
					new provider('http://localhost:3000', {
						ttl: {
							default() {
								return 600;
							}
						}
					});
				}
			];

			okay.forEach((fn) => {
				expect(fn).not.to.throw();
			});

			okay = [
				() => {
					new provider('http://localhost:3000', { ttl: { AccessToken: 1 } });
				},
				() => {
					new provider('http://localhost:3000', {
						ttl: { AccessToken: Number.MAX_SAFE_INTEGER }
					});
				},
				() => {
					new provider('http://localhost:3000', {
						ttl: {
							AccessToken() {
								return 600;
							}
						}
					});
				}
			];

			okay.forEach((fn) => {
				expect(fn).not.to.throw();
			});
		});
	});

	it('validates configuration clientAuthMethods members', () => {
		expect(() => {
			new provider('http://localhost:3000', { clientAuthMethods: ['foo'] });
		}).to.throw(
			"only supported clientAuthMethods are 'none', 'client_secret_basic', 'client_secret_jwt', 'client_secret_post', and 'private_key_jwt'"
		);
	});
});
