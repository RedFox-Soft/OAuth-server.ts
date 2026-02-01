import { describe, it, expect } from 'bun:test';
import { Grant } from 'lib/models/grant.js';

describe('Grant', () => {
	it('manages OIDC Scope', function () {
		const grant = new Grant();
		expect(grant.getOIDCScope()).toBe('');
		grant.addOIDCScope('openid');
		grant.addOIDCScope(['email']);
		grant.addOIDCScope(new Set(['profile']));
		expect(grant.getOIDCScope()).toBe('openid email profile');
		grant.addOIDCScope('openid openid');
		grant.addOIDCScope(['email', 'email']);
		grant.addOIDCScope(new Set(['profile', 'profile']));
		expect(grant.getOIDCScope()).toBe('openid email profile');
		grant.addOIDCScope('address');
		grant.rejectOIDCScope('email');
		grant.rejectOIDCScope(['profile']);
		grant.rejectOIDCScope(new Set(['address']));
		expect(grant.getOIDCScope()).toBe('openid');
		expect(grant.getRejectedOIDCScope()).toBe('email profile address');
		grant.rejectOIDCScope('phone');
		expect(grant.getOIDCScopeEncountered()).toBe(
			'openid email profile address phone'
		);

		grant.rejected = undefined;

		expect(grant.getOIDCScopeFiltered(new Set(['email', 'profile']))).toBe(
			'email profile'
		);
		expect(
			grant.getOIDCScopeFiltered(new Set(['email', 'profile', 'missing']))
		).toBe('email profile');
		expect(grant.getOIDCScopeFiltered(['email', 'profile'])).toBe(
			'email profile'
		);
		expect(grant.getOIDCScopeFiltered(['email', 'profile', 'missing'])).toBe(
			'email profile'
		);
	});

	it('manages OIDC Claims', function () {
		const grant = new Grant();
		expect(grant.getOIDCClaims()).toEqual([]);
		grant.addOIDCClaims(['sub']);
		grant.addOIDCClaims(['email']);
		grant.addOIDCClaims(new Set(['name']));
		expect(grant.getOIDCClaims()).toEqual(['sub', 'email', 'name']);
		grant.addOIDCClaims(['sub', 'sub']);
		grant.addOIDCClaims(['email', 'email']);
		grant.addOIDCClaims(new Set(['name', 'name']));
		expect(grant.getOIDCClaims()).toEqual(['sub', 'email', 'name']);
		grant.addOIDCClaims(['nickname']);
		grant.rejectOIDCClaims(['email']);
		grant.rejectOIDCClaims(['name']);
		grant.rejectOIDCClaims(new Set(['nickname']));
		expect(grant.getOIDCClaims()).toEqual(['sub']);
		expect(grant.getRejectedOIDCClaims()).toEqual([
			'email',
			'name',
			'nickname'
		]);
		grant.rejectOIDCClaims(['phone']);
		expect(grant.getOIDCClaimsEncountered()).toEqual([
			'sub',
			'email',
			'name',
			'nickname',
			'phone'
		]);

		grant.rejected = undefined;

		expect(grant.getOIDCClaimsFiltered(new Set(['email', 'name']))).toEqual([
			'email',
			'name'
		]);
		expect(
			grant.getOIDCClaimsFiltered(new Set(['email', 'name', 'missing']))
		).toEqual(['email', 'name']);
		expect(grant.getOIDCClaimsFiltered(['email', 'name'])).toEqual([
			'email',
			'name'
		]);
		expect(grant.getOIDCClaimsFiltered(['email', 'name', 'missing'])).toEqual([
			'email',
			'name'
		]);
	});

	it('manages Resource Scope', function () {
		const grant = new Grant();
		const resource = 'urn:example:rs';
		expect(grant.getResourceScope(resource)).toBe('');
		grant.addResourceScope(resource, 'read');
		grant.addResourceScope(resource, ['create']);
		grant.addResourceScope(resource, new Set(['delete']));
		expect(grant.getResourceScope(resource)).toBe('read create delete');
		grant.addResourceScope(resource, 'read read');
		grant.addResourceScope(resource, ['create', 'create']);
		grant.addResourceScope(resource, new Set(['delete', 'delete']));
		expect(grant.getResourceScope(resource)).toBe('read create delete');
		grant.addResourceScope(resource, 'update');
		grant.rejectResourceScope(resource, 'create');
		grant.rejectResourceScope(resource, ['delete']);
		grant.rejectResourceScope(resource, new Set(['update']));
		expect(grant.getResourceScope(resource)).toBe('read');
		expect(grant.getRejectedResourceScope(resource)).toBe(
			'create delete update'
		);
		grant.rejectResourceScope(resource, 'phone');
		expect(grant.getResourceScopeEncountered(resource)).toBe(
			'read create delete update phone'
		);

		grant.rejected = undefined;

		expect(
			grant.getResourceScopeFiltered(resource, new Set(['create', 'delete']))
		).toBe('create delete');
		expect(
			grant.getResourceScopeFiltered(
				resource,
				new Set(['create', 'delete', 'missing'])
			)
		).toBe('create delete');
		expect(grant.getResourceScopeFiltered(resource, ['create', 'delete'])).toBe(
			'create delete'
		);
		expect(
			grant.getResourceScopeFiltered(resource, ['create', 'delete', 'missing'])
		).toBe('create delete');
	});
});
