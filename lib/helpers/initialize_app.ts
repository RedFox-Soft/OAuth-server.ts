import instance from './weak_cache.ts';
import query from 'lib/response_modes/query.js';
import { formPost } from 'lib/html/formPost.js';
import jwt from 'lib/response_modes/jwt.js';

export default function initializeApp() {
	const { features } = instance(this);

	this.registerResponseMode('query', query);
	this.registerResponseMode('form_post', formPost);

	if (features.jwtResponseModes.enabled) {
		this.registerResponseMode('jwt', jwt);

		['query', 'form_post'].forEach((mode) => {
			this.registerResponseMode(`${mode}.jwt`, jwt);
		});
	}
}
