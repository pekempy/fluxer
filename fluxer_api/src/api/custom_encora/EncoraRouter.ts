// SPDX-License-Identifier: AGPL-3.0-or-later

import {randomUUID} from 'node:crypto';
import {AdminACLs} from '@fluxer/constants/src/AdminACLs';
import {ConnectionTypes, ConnectionVisibilityFlags} from '@fluxer/constants/src/ConnectionConstants';
import {ConnectionResponse} from '@fluxer/schema/src/domains/connection/ConnectionSchemas';
import {z} from 'zod';
import {createUserID} from '../BrandedTypes';
import {mapConnectionToResponse} from '../connection/ConnectionMappers';
import {requireAdminACL} from '../middleware/AdminMiddleware';
import {OpenAPI} from '../middleware/ResponseTypeMiddleware';
import {getGatewayService} from '../middleware/ServiceRegistry';
import {getConnectionRepository, getUserRepository} from '../middleware/ServiceSingletons';
import type {HonoApp} from '../types/HonoEnv';
import {Validator} from '../Validator';

const LinkEncoraRequest = z.object({
	user_id: z.string().describe('The Prelude/Fluxer user ID (snowflake) to link'),
	encora_username: z.string().min(1).describe("The user's Encora username"),
	encora_slug: z.string().min(1).optional().describe("The user's Encora profile slug (used for profile link)"),
	custom_badge_url: z.string().url().optional().describe('Custom badge image URL'),
	custom_badge_link: z.string().url().optional().describe('Custom badge profile link URL'),
});

export function EncoraRouter(app: HonoApp): void {
	// 1. Intercept connection deletion
	// This endpoint is checked first because it's mounted before ConnectionController.
	// We check if the connection ID points to an *.encora.it domain connection and block it.
	app.delete('/users/@me/connections/:type/:connection_id', async (ctx, next) => {
		const {type, connection_id} = ctx.req.param();
		const user = ctx.get('user');
		if (user && type === ConnectionTypes.DOMAIN) {
			const repository = getConnectionRepository();
			const connection = await repository.findById(user.id, type, connection_id);
			if (connection && (connection.name.endsWith('.encora.it') || connection.name === 'encora.it')) {
				return ctx.json({error: 'This connection is managed by Encora and cannot be removed.'}, 403);
			}
		}
		// Delegate to the original connection deletion controller for other connections
		return await next();
	});

	// 2. Admin endpoint to link account
	app.post(
		'/admin/users/link-encora',
		requireAdminACL(AdminACLs.USER_UPDATE_FLAGS),
		Validator('json', LinkEncoraRequest),
		OpenAPI({
			operationId: 'link_encora_connection',
			summary: 'Link Encora connection',
			responseSchema: ConnectionResponse,
			statusCode: 200,
			security: ['adminApiKey'],
			tags: ['Admin', 'Connections'],
			description:
				'Admin-only endpoint to link or update a user connection to their Encora profile. Automatically verified as a domain connection. Requires USER_UPDATE_FLAGS permission.',
		}),
		async (ctx) => {
			const body = ctx.req.valid('json');
			const userId = createUserID(BigInt(body.user_id));
			const encoraUsername = body.encora_username;
			const encoraSlug = body.encora_slug ?? encoraUsername;
			const domainName = `${encoraUsername}.encora.it`.toLowerCase();

			// Use provided badge URLs or set defaults
			const customBadgeUrl = body.custom_badge_url ?? 'https://encora.it/images/favicon.png';
			const customBadgeLink = body.custom_badge_link ?? `https://encora.it/traders/${encoraSlug}`;

			const repository = getConnectionRepository();
			const userRepository = getUserRepository();
			const gateway = getGatewayService();

			// Update user with custom badge fields
			await userRepository.patchUpsert(userId, {
				custom_badge_url: customBadgeUrl,
				custom_badge_link: customBadgeLink,
			});

			// Check if connection already exists
			const existing = await repository.findByTypeAndIdentifier(userId, ConnectionTypes.DOMAIN, domainName);
			let resultRow;
			const now = new Date();

			if (existing) {
				// Update existing connection
				await repository.update(userId, ConnectionTypes.DOMAIN, existing.connection_id, {
					name: domainName,
					verified: true,
					verified_at: existing.verified_at ?? now,
					last_verified_at: now,
				});
				resultRow = (await repository.findById(userId, ConnectionTypes.DOMAIN, existing.connection_id))!;
			} else {
				// Create new connection
				const count = await repository.count(userId);
				const connectionId = randomUUID();
				resultRow = await repository.create({
					user_id: userId,
					connection_id: connectionId,
					connection_type: ConnectionTypes.DOMAIN,
					identifier: domainName,
					name: domainName,
					visibility_flags: ConnectionVisibilityFlags.EVERYONE,
					sort_order: count,
					verification_token: '',
					verified: true,
					verified_at: now,
					last_verified_at: now,
				});
			}

			// Broadcast gateway update to push change in real-time to the active clients
			const connections = await repository.findByUserId(userId);
			await gateway.dispatchPresence({
				userId,
				event: 'USER_CONNECTIONS_UPDATE',
				data: {connections: connections.map(mapConnectionToResponse)},
			});

			return ctx.json(mapConnectionToResponse(resultRow));
		},
	);
}
