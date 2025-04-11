import opaque from './opaque.ts';
import jwt from './jwt.ts';
import dynamic from './dynamic.ts';

export default (provider) => {
	const result = {
		opaque: opaque(provider) // no dependencies
	};

	result.jwt = jwt(provider, result); // depends on opaque
	result.dynamic = dynamic(provider, result); // depends on all

	return result;
};
