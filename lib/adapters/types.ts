import { ObjectId } from 'mongodb';

export interface User {
	_id: ObjectId | string;
	sub: string;
	email: string;
	verified: boolean;
	password: string;
	active: boolean;
	createdAt: Date;
	updatedAt: Date;
	lastLoginAt: Date | null;
}
