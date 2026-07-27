import query from './query.ts';
import jwt from './jwt.ts';
import { formPost } from '../html/formPost.js';
import { ApplicationConfig } from '../configs/application.js';

// Response-mode handlers are plain modules, so they are resolved from here directly instead of
// being registered into a Map held on the provider at initialisation. None of them uses `this`,
// which is why the old registration step could bind the provider and nothing noticed.
const BASE = {
	query,
	form_post: formPost
};

// Gated on the JWT response-mode flag, read per lookup rather than sampled once during
// initialisation — the same live-read rule the rest of ApplicationConfig follows.
const JWT_SECURED = {
	jwt,
	'query.jwt': jwt,
	'form_post.jwt': jwt
};

type ResponseModeName = keyof typeof BASE | keyof typeof JWT_SECURED;

export const responseModes = {
	get(name: string) {
		if (name in BASE) return BASE[name as keyof typeof BASE];
		if (ApplicationConfig['responseMode.jwt.enabled'] && name in JWT_SECURED) {
			return JWT_SECURED[name as keyof typeof JWT_SECURED];
		}
		return undefined;
	},
	has(name: string) {
		return responseModes.get(name) !== undefined;
	}
};

export type { ResponseModeName };
