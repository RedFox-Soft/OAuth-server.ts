import { renderToString } from 'react-dom/server';
import React, { StrictMode } from 'react';
import { LoginPage } from './loginPage.tsx';
import { ConsentPage } from './consentPage.tsx';

export const loginServer = (uid: string) => {
	return renderToString(
		<StrictMode>
			<LoginPage uid={uid} />
		</StrictMode>
	);
};

export const consentServer = (uid: string) => {
	return renderToString(
		<StrictMode>
			<ConsentPage uid={uid} />
		</StrictMode>
	);
}
