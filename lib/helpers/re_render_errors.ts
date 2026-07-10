export class ReRenderError extends Error {
	userCode?: string;
	status: number;
	expose: boolean;

	constructor(message: string, userCode?: string) {
		super(message);
		if (userCode) this.userCode = userCode;
		this.message = message;
		this.name = this.constructor.name;
		this.status = 200;
		this.expose = true;
		Error.captureStackTrace(this, this.constructor);
	}
}
export class NotFoundError extends ReRenderError {
	constructor(userCode?: string) {
		super('the code was not found', userCode);
	}
}
export class ExpiredError extends ReRenderError {
	constructor(userCode?: string) {
		super('the code has expired', userCode);
	}
}
export class AbortedError extends ReRenderError {
	constructor() {
		super('the interaction was aborted');
	}
}
export class AlreadyUsedError extends ReRenderError {
	constructor(userCode?: string) {
		super('code has already been used', userCode);
	}
}
export class NoCodeError extends ReRenderError {
	constructor() {
		super('no code submitted');
	}
}
