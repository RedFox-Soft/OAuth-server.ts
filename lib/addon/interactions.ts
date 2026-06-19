import { shouldChange } from './_warn.ts';

export function deviceInfo(ctx) {
	return {
		ip: ctx.ip,
		ua: ctx.get('user-agent')
	};
}

export async function userCodeInputSource(ctx, form, out, err) {
	// @param ctx - koa request context
	// @param form - form source (id="op.deviceInputForm") to be embedded in the page and submitted
	//   by the End-User.
	// @param out - if an error is returned the out object contains details that are fit to be
	//   rendered, i.e. does not include internal error messages
	// @param err - error object with an optional userCode property passed when the form is being
	//   re-rendered due to code missing/invalid/expired
	shouldChange(
		'features.deviceFlow.userCodeInputSource',
		'customize the look of the user code input page'
	);
	let msg;
	if (err && (err.userCode || err.name === 'NoCodeError')) {
		msg = '<p class="red">The code you entered is incorrect. Try again</p>';
	} else if (err && err.name === 'AbortedError') {
		msg = '<p class="red">The Sign-in request was interrupted</p>';
	} else if (err) {
		msg = '<p class="red">There was an error processing your request</p>';
	} else {
		msg = '<p>Enter the code displayed on your device</p>';
	}
	ctx.body = `<!DOCTYPE html>
    <html>
    <head>
      <meta http-equiv="X-UA-Compatible" content="IE=edge">
      <meta charset="utf-8">
      <title>Sign-in</title>
      <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
      <meta http-equiv="x-ua-compatible" content="ie=edge">
      <style>
        @import url(https://fonts.googleapis.com/css?family=Roboto:400,100);h1,h1+p{font-weight:100;text-align:center}body{font-family:Roboto,sans-serif;margin-top:25px;margin-bottom:25px}.container{padding:0 40px 10px;width:274px;background-color:#F7F7F7;margin:0 auto 10px;border-radius:2px;box-shadow:0 2px 2px rgba(0,0,0,.3);overflow:hidden}h1{font-size:2.3em}p.red{color:#d50000}input[type=email],input[type=password],input[type=text]{height:44px;font-size:16px;width:100%;margin-bottom:10px;-webkit-appearance:none;background:#fff;border:1px solid #d9d9d9;border-top:1px solid silver;padding:0 8px;box-sizing:border-box;-moz-box-sizing:border-box}[type=submit]{width:100%;display:block;margin-bottom:10px;position:relative;text-align:center;font-size:14px;font-family:Arial,sans-serif;font-weight:700;height:36px;padding:0 8px;border:0;color:#fff;text-shadow:0 1px rgba(0,0,0,.1);background-color:#4d90fe;cursor:pointer}[type=submit]:hover{border:0;text-shadow:0 1px rgba(0,0,0,.3);background-color:#357ae8}input[type=text]{text-transform:uppercase;text-align: center}input[type=text]::placeholder{text-transform: none}
      </style>
    </head>
    <body>
      <div class="container">
        <h1>Sign-in</h1>
        ${msg}
        ${form}
        <button type="submit" form="op.deviceInputForm">Continue</button>
      </div>
    </body>
    </html>`;
}

export async function userCodeConfirmSource(
	ctx,
	form,
	client,
	deviceInfo,
	userCode
) {
	// @param ctx - koa request context
	// @param form - form source (id="op.deviceConfirmForm") to be embedded in the page and
	//   submitted by the End-User.
	// @param deviceInfo - device information from the device_authorization_endpoint call
	// @param userCode - formatted user code by the configured mask
	shouldChange(
		'features.deviceFlow.userCodeConfirmSource',
		'customize the look of the user code confirmation page'
	);
	const { clientId, clientName, clientUri, logoUri, policyUri, tosUri } =
		ctx.oidc.client;
	ctx.body = `<!DOCTYPE html>
    <html>
    <head>
      <meta http-equiv="X-UA-Compatible" content="IE=edge">
      <meta charset="utf-8">
      <title>Device Login Confirmation</title>
      <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
      <style>
        @import url(https://fonts.googleapis.com/css?family=Roboto:400,100);.help,h1,h1+p{text-align:center}h1,h1+p{font-weight:100}body{font-family:Roboto,sans-serif;margin-top:25px;margin-bottom:25px}.container{padding:0 40px 10px;width:274px;background-color:#f7f7f7;margin:0 auto 10px;border-radius:2px;box-shadow:0 2px 2px rgba(0,0,0,.3);overflow:hidden}h1{font-size:2.3em}button[autofocus]{width:100%;display:block;margin-bottom:10px;position:relative;font-size:14px;font-family:Arial,sans-serif;font-weight:700;height:36px;padding:0 8px;border:0;color:#fff;text-shadow:0 1px rgba(0,0,0,.1);background-color:#4d90fe;cursor:pointer}button[autofocus]:hover{border:0;text-shadow:0 1px rgba(0,0,0,.3);background-color:#357ae8}button[name=abort]{background:0 0!important;border:none;padding:0!important;font:inherit;cursor:pointer}a,button[name=abort]{text-decoration:none;color:#666;font-weight:400;display:inline-block;opacity:.6}.help{width:100%;font-size:12px}code{font-size:2em}
      </style>
    </head>
    <body>
      <div class="container">
        <h1>Confirm Device</h1>
        <p>
          <strong>${clientName || clientId}</strong>
          <br/><br/>
          The following code should be displayed on your device<br/><br/>
          <code>${userCode}</code>
          <br/><br/>
          <small>If you did not initiate this action, the code does not match or are unaware of such device in your possession please close this window or click abort.</small>
        </p>
        ${form}
        <button autofocus type="submit" form="op.deviceConfirmForm">Continue</button>
        <div class="help">
          <button type="submit" form="op.deviceConfirmForm" value="yes" name="abort">[ Abort ]</button>
        </div>
      </div>
    </body>
    </html>`;
}

export async function successSource(ctx) {
	// @param ctx - koa request context
	shouldChange(
		'features.deviceFlow.successSource',
		'customize the look of the device code success page'
	);
	const {
		clientId,
		clientName,
		clientUri,
		initiateLoginUri,
		logoUri,
		policyUri,
		tosUri
	} = ctx.oidc.client;
	ctx.body = `<!DOCTYPE html>
    <html>
    <head>
      <meta http-equiv="X-UA-Compatible" content="IE=edge">
      <meta charset="utf-8">
      <title>Sign-in Success</title>
      <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
      <style>
        @import url(https://fonts.googleapis.com/css?family=Roboto:400,100);h1,h1+p{font-weight:100;text-align:center}body{font-family:Roboto,sans-serif;margin-top:25px;margin-bottom:25px}.container{padding:0 40px 10px;width:274px;background-color:#F7F7F7;margin:0 auto 10px;border-radius:2px;box-shadow:0 2px 2px rgba(0,0,0,.3);overflow:hidden}h1{font-size:2.3em}
      </style>
    </head>
    <body>
      <div class="container">
        <h1>Sign-in Success</h1>
        <p>Your sign-in ${clientName ? `with ${clientName}` : ''} was successful, you can now close this page.</p>
      </div>
    </body>
    </html>`;
}
