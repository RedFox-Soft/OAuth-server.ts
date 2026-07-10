import htmlSafe from './html_safe.ts';

export function input(
	action: string,
	csrfToken: string,
	code: string,
	charset: string
) {
	const attributes =
		charset === 'digits' ? 'pattern="[0-9]*" inputmode="numeric" ' : '';

	return `<form id="op.deviceInputForm" novalidate method="post" action="${action}">
  <input type="hidden" name="xsrf" value="${csrfToken}"/>
  <input
    ${code ? `value="${htmlSafe(code)}" ` : ''}${attributes}type="text" name="user_code" placeholder="Enter code" onfocus="this.select(); this.onfocus = undefined;" autofocus autocomplete="off"></input>
  </form>`;
}

export function confirm(action: string, csrfToken: string, code: string) {
	return `<form id="op.deviceConfirmForm" method="post" action="${action}">
<input type="hidden" name="xsrf" value="${csrfToken}"/>
<input type="hidden" name="user_code" value="${htmlSafe(code)}"/>
<input type="hidden" name="confirm" value="yes"/>
</form>`;
}
