import { InvalidRequest } from '../../helpers/errors.js';
import certificateThumbprint from '../../helpers/certificate_thumbprint.js';
import { type BaseToken, type BaseTokenPayloadType } from '../base_token.js';
import { type X509Certificate } from 'node:crypto';

const x5t = 'x5t#S256';
const jkt = 'jkt';

type ConstrainedPayload = BaseTokenPayloadType & {
	'x5t#S256'?: string;
	jkt?: string;
};

export default function constrained<TPayload extends ConstrainedPayload>(
	superclass: typeof BaseToken<TPayload>
) {
	return class extends superclass {
		setThumbprint(prop: 'x5t', input: string | X509Certificate): void;
		setThumbprint(prop: 'jkt', input: string): void;
		setThumbprint(prop: 'x5t' | 'jkt', input: string | X509Certificate): void {
			if (prop === 'x5t') {
				if (this.payload[jkt]) {
					throw new InvalidRequest(
						'multiple proof-of-posession mechanisms are not allowed'
					);
				}
				this.payload[x5t] = certificateThumbprint(input);
			} else if (prop === 'jkt') {
				if (this.payload[x5t]) {
					throw new InvalidRequest(
						'multiple proof-of-posession mechanisms are not allowed'
					);
				}
				if (typeof input !== 'string') {
					throw new InvalidRequest('jkt thumbprint must be a string');
				}
				this.payload[jkt] = input;
			}
		}

		isSenderConstrained() {
			if (this.payload[jkt] || this.payload[x5t]) {
				return true;
			}

			return false;
		}

		get tokenType() {
			if (this.payload[jkt]) {
				return 'DPoP';
			}

			return 'Bearer';
		}
	};
}
