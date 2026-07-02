import query from 'lib/response_modes/query.js';
import { formPost } from 'lib/html/formPost.js';
import jwt from 'lib/response_modes/jwt.js';
import { ApplicationConfig } from 'lib/configs/application.js';

export default function initializeApp() {
	this.registerResponseMode('query', query);
	this.registerResponseMode('form_post', formPost);

	if (ApplicationConfig['responseMode.jwt.enabled']) {
		this.registerResponseMode('jwt', jwt);

		['query', 'form_post'].forEach((mode) => {
			this.registerResponseMode(`${mode}.jwt`, jwt);
		});
	}
}
