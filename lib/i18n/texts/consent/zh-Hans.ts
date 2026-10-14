import type { ConsentTexts } from './index.js';

export const zhHans: ConsentTexts = {
	pageTitle: '允许访问',

	headline: {
		signIn: '登录{app}',
		ownAccess: '{app}请求访问您的{service}账户',
		app: '应用「{app}」请求访问您的账户',
		device: '是否允许设备访问？'
	},

	host: {
		label: '应用地址',
		documentLabel: '应用发布于',
		privateUse: '此设备上的某个应用（{scheme}）——{service}无法确认是哪一个',
		notChecked: '{service}尚未核实此应用'
	},

	account: {
		signedInAs: '当前登录账户：{account}',
		switch: '切换账户'
	},

	signIn: {
		shares: '{service}将与该应用共享：',
		confirmsIdentity: '{service}将向该应用确认是您本人。',
		noPassword: '该应用不会获得您的密码。'
	},

	groups: {
		see: '该应用将能够查看：',
		act: '该应用将能够代您执行：',
		undescribed: '其他权限（未作说明）：'
	},

	categories: {
		profile: '您的姓名和头像',
		profileName: '您的姓名',
		profilePhoto: '您的头像',
		profileDetails: '您个人资料中的其他信息',
		email: '您的电子邮件地址',
		address: '您的邮寄地址',
		phone: '您的电话号码',
		groups: '您所属的组'
	},

	resource: {
		heading: '适用于',
		technicalNames: '技术名称',
		codesIn: '{resource}中的{codes}',
		undescribedOwner: '{owner}的所有者未对以下内容作出说明：',
		undescribedAdministrator: '{service}的管理员未对以下内容作出说明：'
	},

	rarFields: {
		actions: '操作',
		locations: '位置',
		datatypes: '数据类型',
		privileges: '特权',
		identifier: '标识符'
	},

	lifetime: '即使您没有在使用，该应用也会保留此访问权限，直至{date}。',

	repeat: {
		alreadyAllowed: '您之前已允许：{items}。',
		alsoAsks: '现在该应用还请求：',
		nothingNew: '没有新的请求。该应用只会获得您之前允许的内容：{items}。',
		afterApproval: '您允许后，该应用将能够：',
		afterApprovalItems: '{items}。',
		afterApprovalItemsAndChoice: '{items}，以及您在上方选择的任何内容。'
	},

	choices: {
		fixedHeading: '登录所必需：',
		refusedBefore: '您上次没有允许此项',
		offline: '在您未使用时也保留访问权限',
		offlineUntil: '直至{date}',
		rarTogether: '这些内容只能与其余内容一并允许，或者全部不允许。'
	},

	nothingRequested: '「{app}」没有请求您的任何数据。',

	warning: {
		hiddenPrefix: '警告：',
		adminTitle: '管理员权限。',
		admin:
			'该应用将能够执行您在{service}控制台中可以执行的任何操作，例如删除应用、用户和密钥。',
		loopback:
			'此计算机上的某个程序将接收响应。{service}无法判断是哪一个程序。仅当「{app}」是您刚刚亲自启动的，才继续。',
		deviceQuestion: '您的设备上是否显示了此代码？',
		deviceSent: '如果此代码是别人发给您的，请选择「不允许」。',
		deviceRequested: '{ago}发起的请求。',
		justNow: '刚刚',
		unverified:
			'「{app}」的名称是它自己设定的。仅当此操作是您自己在{host}上发起的，才继续。',
		unverifiedNoHost:
			'「{app}」的名称是它自己设定的。仅当此操作是您自己发起的，才继续。',
		hostMismatch: '该应用的地址与它要将您转到的地址不一致。'
	},

	device: {
		client: '输入此代码的设备上的应用：',
		next: '然后返回您的设备。'
	},

	next: {
		loopback: '接下来，此计算机上的某个程序将接收响应。'
	},

	links: {
		label: '关于{app}',
		policy: '{app}的隐私政策',
		terms: '{app}的服务条款',
		external: '（在新标签页中打开外部网站）'
	},

	revokeHint: {
		sentence: '您可以随时在{link}上移除此访问权限。',
		link: '已连接应用页面'
	},

	buttons: {
		deny: '不允许',
		allow: '允许',
		cancel: '取消',
		continue: '继续'
	}
};
