export interface User {
	_id: string;
	email: string;
	verified: boolean;
	password: string;
	active: boolean;
	createdAt: Date;
	updatedAt: Date;
	lastLoginAt: Date | null;
}
