import { renderToString } from 'react-dom/server';
import React, { StrictMode } from 'react';
import { LoginPage } from './loginPage.tsx';

export const loginServer = (uid: string) => {
	return renderToString(
		<StrictMode>
			<LoginPage uid={uid} />
		</StrictMode>
	);
};
