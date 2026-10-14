import type { AccountTexts } from './index.js';

export const zhHans: AccountTexts = {
	clientName: '您的账户页面',
	title: '已连接应用',
	signedInAs: '当前登录账户：{email}',
	signOut: '退出登录',
	intro:
		'这些应用可以访问您的账户。移除其中一个应用会让您从该应用退出登录，它需要再次征得您的同意才能重新获得访问权限。',
	empty: '没有任何应用可以访问您的账户。',
	deletedApp: '一个已不存在的应用',
	signsInAt: '在{hosts}为您登录',
	signsInAtMore: {
		other: '在{hosts}以及另外{count}个地址为您登录'
	},
	onThisDevice: '此设备上的某个应用',
	trusted: '属于{service}。它无需征求您的同意，即可获得所请求的访问权限。',
	canSee: '可以查看',
	canDo: '可以代您执行',
	otherAccess: '其他访问权限',
	confirmIdentity: '可以确认您的身份',
	technicalNames: '技术名称',
	given: '授权时间：{date}',
	lastToken: '上次获得令牌：{date}',
	dateTime: '{dateTime} UTC',
	keepsAccess: '退出登录后仍保留访问权限',
	remove: '移除访问权限',
	cancel: '取消',
	confirmTitle: '要移除{app}的访问权限吗？',
	confirmEffect: '{app}将被退出登录，并失去对您账户的访问权限。',
	confirmAsksAgain: '下次它需要再次征得您的同意。',
	confirmReturnsSilently: '下次您使用它时，它会直接为您登录，不再询问。',
	done: '已移除{app}的访问权限。',
	gone: '该应用已不再拥有您账户的访问权限。',
	expiredTitle: '此次登录已过期',
	expired: '已连接应用页面的登录耗时过长，或者是在其他地方发起的。',
	notSignedInTitle: '您没有登录',
	notSignedIn: '要查看已连接应用页面，您需要先登录。',
	failedTitle: '出现错误',
	failed: '我们无法让您登录已连接应用页面。',
	tryAgain: '前往已连接应用页面',
	refusedTitle: '请求被拒绝',
	refused: '此请求并非来自您的已连接应用页面，因此未做任何更改。'
};
