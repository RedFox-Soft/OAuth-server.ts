import React from 'react';
import { Button, Card, Typography, Space } from 'antd';
import type { ConsentView } from './consentView.js';

const { Title, Paragraph, Text } = Typography;

export const ConsentPage: React.FC<ConsentView> = ({
	clientName,
	account,
	permissions
}) => (
	<Space
		orientation="vertical"
		style={{
			width: '100%',
			height: '100%',
			justifyContent: 'center',
			alignItems: 'center'
		}}
	>
		<Card style={{ maxWidth: 400, width: '100%' }}>
			<Title level={3}>Consent Required</Title>
			<Paragraph>
				<b>{clientName}</b> is requesting access to your account.
			</Paragraph>
			{account ? (
				<Paragraph>
					Signed in as <Text code>{account}</Text>
				</Paragraph>
			) : null}
			{permissions.length ? (
				<>
					<Paragraph>This will allow it to access:</Paragraph>
					{permissions.map((group, groupIndex) => (
						<div key={group.resourceIndicator ?? group.kind ?? groupIndex}>
							{group.resourceIndicator ? (
								<Paragraph style={{ marginBottom: 4 }}>
									<b>{group.resourceIndicator}</b>
								</Paragraph>
							) : null}
							<ul>
								{group.items.map((item) => (
									<li key={item.token}>
										{item.label} (<Text code>{item.token}</Text>)
									</li>
								))}
							</ul>
						</div>
					))}
				</>
			) : (
				<Paragraph>No additional permissions are requested.</Paragraph>
			)}
			<form method="post">
				<Space style={{ width: '100%', justifyContent: 'flex-end' }}>
					<Button
						htmlType="submit"
						name="action"
						value="cancel"
					>
						Cancel
					</Button>
					<Button
						type="primary"
						htmlType="submit"
						name="action"
						value="allow"
					>
						Allow
					</Button>
				</Space>
			</form>
		</Card>
	</Space>
);
