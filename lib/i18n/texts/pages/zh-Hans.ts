import type { PagesTexts } from './index.js';

export const zhHans: PagesTexts = {
	error: {
		headings: {
			notFound: '页面不存在',
			forbidden: '不允许此请求',
			serverError: '我们这边出了点问题',
			failed: '无法完成此请求'
		},
		details: '供应用开发者参考的详细信息：',
		reference: '（参考编号：{reference}）'
	},
	device: {
		input: {
			title: '登录',
			heading: '登录',
			prompt: '请输入您设备上显示的代码',
			continue: '继续'
		},
		errors: {
			incorrectCode: '您输入的代码不正确，请重试',
			aborted: '登录请求已中断',
			unfinished: '无法完成登录。已通知您的设备。',
			failed: '处理您的请求时出错'
		},
		confirm: {
			title: '设备登录确认',
			heading: '确认设备',
			codeIntro: '您的设备上应显示以下代码',
			warning:
				'如果此操作不是您发起的、代码不一致，或者您不知道自己有这样一台设备，请关闭此窗口或点击「中止」。',
			continue: '继续',
			abort: '[ 中止 ]'
		},
		success: {
			title: '登录成功',
			heading: '登录成功',
			message: '您已成功登录，现在可以关闭此页面。',
			messageWithApp: '您已成功登录{app}，现在可以关闭此页面。'
		}
	},
	userCode: {
		placeholder: '输入代码'
	},
	logout: {
		title: '退出登录',
		logoAlt: '徽标',
		question: '您要退出登录吗？',
		stay: '否，保持登录',
		signOut: '是，退出登录'
	},
	logoutSuccess: {
		title: '退出登录',
		logoAlt: '徽标',
		message: '您已成功退出登录'
	},
	formPost: {
		title: '正在返回应用',
		noscript: '您的浏览器不支持 JavaScript，或者您已将其禁用。',
		continue: '继续'
	}
};
