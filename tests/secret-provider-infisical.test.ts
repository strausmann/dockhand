/**
 * Unit tests for the Infisical secret provider.
 *
 * Infisical is open-source and self-hostable, so it is integration-testable
 * against a real instance later. Here we exercise the provider in isolation by
 * mocking undici's `request`, covering:
 *   - a successful bulk pull mapping { secretKey, secretValue } → Record
 *   - the selector / config.path / '/' precedence for the queried path
 *   - an auth failure (HTTP 401) surfacing as a thrown error
 *   - testConnection returning ok on 2xx and a helpful error otherwise
 *   - resolveSecretReferences throwing UnsupportedOperationError (bulk-only)
 *   - Universal Auth (Machine Identity): login exchange, access-token caching,
 *     expiry-triggered re-login, and auth-config validation (token XOR
 *     clientId+clientSecret)
 */

import { describe, it, expect, mock, beforeEach } from 'bun:test';

/**
 * A single mock for undici's `request`. Registered before the provider is
 * imported so the provider's `import { request } from 'undici'` binds to it.
 * Each test sets its behaviour via `requestMock.mockImplementation(...)`.
 */
const requestMock = mock();
mock.module('undici', () => ({ request: requestMock }));

const { infisicalProvider, __resetInfisicalUniversalAuthCacheForTests } = await import(
	'../src/lib/server/secretproviders/infisical.ts'
);
const { UnsupportedOperationError } = await import('../src/lib/server/secretproviders/shared.ts');

/** Builds an undici-style response with json()/text() bodies. */
function response(statusCode: number, json: unknown, text = '') {
	return {
		statusCode,
		body: {
			json: async () => json,
			text: async () => text
		}
	};
}

const baseConfig = {
	host: 'https://app.infisical.com',
	token: 'st.token.value',
	projectId: 'proj-123',
	environment: 'prod',
	path: '/'
};

/** Same coordinates as baseConfig, but authenticating via Universal Auth. */
const universalAuthConfig = {
	host: 'https://app.infisical.com',
	clientId: 'client-abc',
	clientSecret: 'secret-xyz',
	projectId: 'proj-123',
	environment: 'prod',
	path: '/'
};

/** A secrets/raw 200 response with a single secret, for tests that don't care about the payload. */
function secretsResponse() {
	return response(200, { secrets: [{ secretKey: 'K', secretValue: 'V' }] });
}

/** A Universal Auth login 200 response. */
function loginResponse(accessToken: string, expiresIn = 3600) {
	return response(200, { accessToken, expiresIn });
}

beforeEach(() => {
	requestMock.mockReset();
	__resetInfisicalUniversalAuthCacheForTests();
});

describe('infisicalProvider capabilities', () => {
	it('advertises bulk-only, no references', () => {
		expect(infisicalProvider.type).toBe('infisical');
		expect(infisicalProvider.label).toBe('Infisical');
		expect(infisicalProvider.supportsBulk).toBe(true);
		expect(infisicalProvider.supportsReferences).toBe(false);
	});

	it('isReference is always false', () => {
		expect(infisicalProvider.isReference('op://vault/item/field')).toBe(false);
		expect(infisicalProvider.isReference('anything')).toBe(false);
		expect(infisicalProvider.isReference(42)).toBe(false);
	});
});

describe('infisicalProvider.resolveBulk', () => {
	it('maps secretKey/secretValue pairs into a flat record', async () => {
		requestMock.mockImplementation(async () =>
			response(200, {
				secrets: [
					{ secretKey: 'DB_PASSWORD', secretValue: 's3cr3t' },
					{ secretKey: 'API_KEY', secretValue: 'abc123' }
				]
			})
		);

		const result = await infisicalProvider.resolveBulk(baseConfig, '');

		expect(result).toEqual({ DB_PASSWORD: 's3cr3t', API_KEY: 'abc123' });

		// Verify the request shape: raw secrets endpoint, bearer auth, and the
		// workspace/environment/path query.
		const [url, opts] = requestMock.mock.calls[0];
		expect(url).toContain('https://app.infisical.com/api/v3/secrets/raw');
		expect(url).toContain('workspaceId=proj-123');
		expect(url).toContain('environment=prod');
		expect(url).toContain('secretPath=%2F');
		expect(opts.method).toBe('GET');
		expect(opts.headers.authorization).toBe('Bearer st.token.value');
	});

	it('tolerates an absent secrets array', async () => {
		requestMock.mockImplementation(async () => response(200, {}));
		const result = await infisicalProvider.resolveBulk(baseConfig, '');
		expect(result).toEqual({});
	});

	it('prefers the selector over config.path for secretPath', async () => {
		requestMock.mockImplementation(async () => response(200, { secrets: [] }));
		await infisicalProvider.resolveBulk({ ...baseConfig, path: '/config' }, '/services/web');
		const [url] = requestMock.mock.calls[0];
		expect(url).toContain('secretPath=%2Fservices%2Fweb');
	});

	it('falls back to config.path when the selector is empty', async () => {
		requestMock.mockImplementation(async () => response(200, { secrets: [] }));
		await infisicalProvider.resolveBulk({ ...baseConfig, path: '/config' }, '');
		const [url] = requestMock.mock.calls[0];
		expect(url).toContain('secretPath=%2Fconfig');
	});

	it('throws on an auth failure (HTTP 401)', async () => {
		requestMock.mockImplementation(async () =>
			response(401, {}, 'Unauthorized: invalid token')
		);
		await expect(infisicalProvider.resolveBulk(baseConfig, '')).rejects.toThrow(/401/);
	});

	it('throws a clear error when the environment is missing', async () => {
		await expect(
			infisicalProvider.resolveBulk({ ...baseConfig, environment: undefined }, '')
		).rejects.toThrow(/Environment is required/);
		// No HTTP call should have been attempted.
		expect(requestMock).not.toHaveBeenCalled();
	});
});

describe('infisicalProvider.resolveSecretReferences', () => {
	it('throws UnsupportedOperationError (bulk-only backend)', async () => {
		await expect(
			infisicalProvider.resolveSecretReferences(baseConfig, ['ref'])
		).rejects.toBeInstanceOf(UnsupportedOperationError);
		await expect(
			infisicalProvider.resolveSecretReferences(baseConfig, ['ref'])
		).rejects.toThrow(/does not support inline references/);
		expect(requestMock).not.toHaveBeenCalled();
	});
});

describe('infisicalProvider.testConnection', () => {
	it('returns ok on a 2xx response', async () => {
		requestMock.mockImplementation(async () => response(200, { secrets: [] }));
		const result = await infisicalProvider.testConnection(baseConfig);
		expect(result.ok).toBe(true);
		const [url] = requestMock.mock.calls[0];
		expect(url).toContain('secretPath=%2F');
	});

	it('returns ok:false with the status on an auth failure', async () => {
		requestMock.mockImplementation(async () => response(401, {}, 'Unauthorized'));
		const result = await infisicalProvider.testConnection(baseConfig);
		expect(result.ok).toBe(false);
		expect(result.error).toContain('401');
	});

	it('does not throw when the transport fails, returns the message', async () => {
		requestMock.mockImplementation(async () => {
			throw new Error('ECONNREFUSED');
		});
		const result = await infisicalProvider.testConnection(baseConfig);
		expect(result.ok).toBe(false);
		expect(result.error).toContain('ECONNREFUSED');
	});

	it('returns a helpful error when projectId is empty (no HTTP call)', async () => {
		const result = await infisicalProvider.testConnection({ ...baseConfig, projectId: '' });
		expect(result.ok).toBe(false);
		expect(result.error).toContain('Project ID');
		expect(requestMock).not.toHaveBeenCalled();
	});

	it('returns a helpful error when environment is empty (no HTTP call)', async () => {
		const result = await infisicalProvider.testConnection({
			...baseConfig,
			environment: undefined
		});
		expect(result.ok).toBe(false);
		expect(result.error).toContain('Environment');
		expect(requestMock).not.toHaveBeenCalled();
	});
});

describe('infisicalProvider Universal Auth (Machine Identity)', () => {
	it('resolveBulk logs in via Universal Auth, then uses the access token as the bearer', async () => {
		requestMock.mockImplementation(async (url: string, opts: any) => {
			if (String(url).includes('/api/v1/auth/universal-auth/login')) {
				return loginResponse('ua-access-token');
			}
			return secretsResponse();
		});

		const result = await infisicalProvider.resolveBulk(universalAuthConfig, '');
		expect(result).toEqual({ K: 'V' });
		expect(requestMock.mock.calls.length).toBe(2);

		const [loginUrl, loginOpts] = requestMock.mock.calls[0];
		expect(loginUrl).toBe('https://app.infisical.com/api/v1/auth/universal-auth/login');
		expect(loginOpts.method).toBe('POST');
		expect(JSON.parse(loginOpts.body)).toEqual({
			clientId: 'client-abc',
			clientSecret: 'secret-xyz'
		});

		const [secretsUrl, secretsOpts] = requestMock.mock.calls[1];
		expect(secretsUrl).toContain('/api/v3/secrets/raw');
		expect(secretsOpts.headers.authorization).toBe('Bearer ua-access-token');
	});

	it('testConnection logs in via Universal Auth before probing the secrets endpoint', async () => {
		requestMock.mockImplementation(async (url: string) => {
			if (String(url).includes('/api/v1/auth/universal-auth/login')) {
				return loginResponse('ua-access-token');
			}
			return secretsResponse();
		});

		const result = await infisicalProvider.testConnection(universalAuthConfig);
		expect(result.ok).toBe(true);
		expect(requestMock.mock.calls.length).toBe(2);
		const [, secretsOpts] = requestMock.mock.calls[1];
		expect(secretsOpts.headers.authorization).toBe('Bearer ua-access-token');
	});

	it('caches the access token across calls against the same host+clientId (logs in once)', async () => {
		requestMock.mockImplementation(async (url: string) => {
			if (String(url).includes('/api/v1/auth/universal-auth/login')) {
				return loginResponse('ua-access-token');
			}
			return secretsResponse();
		});

		await infisicalProvider.resolveBulk(universalAuthConfig, '');
		await infisicalProvider.resolveBulk(universalAuthConfig, '');

		const loginCalls = requestMock.mock.calls.filter(([url]: [string]) =>
			String(url).includes('/api/v1/auth/universal-auth/login')
		);
		expect(loginCalls.length).toBe(1);
		// Two resolveBulk calls, one login + two secret pulls = 3 total requests.
		expect(requestMock.mock.calls.length).toBe(3);
	});

	it('does not share the cached token between different clientIds', async () => {
		requestMock.mockImplementation(async (url: string, opts: any) => {
			if (String(url).includes('/api/v1/auth/universal-auth/login')) {
				const body = JSON.parse(opts.body);
				return loginResponse(`token-for-${body.clientId}`);
			}
			return secretsResponse();
		});

		await infisicalProvider.resolveBulk(universalAuthConfig, '');
		await infisicalProvider.resolveBulk({ ...universalAuthConfig, clientId: 'client-other' }, '');

		const loginCalls = requestMock.mock.calls.filter(([url]: [string]) =>
			String(url).includes('/api/v1/auth/universal-auth/login')
		);
		expect(loginCalls.length).toBe(2);
	});

	it('re-logs in once the cached token is past its (margin-adjusted) expiry', async () => {
		let loginCount = 0;
		requestMock.mockImplementation(async (url: string) => {
			if (String(url).includes('/api/v1/auth/universal-auth/login')) {
				loginCount++;
				// expiresIn below the 60s refresh margin => safe TTL clamps to 0,
				// so the cached entry is already stale by the very next check.
				return loginResponse(`ua-access-token-${loginCount}`, 30);
			}
			return secretsResponse();
		});

		await infisicalProvider.resolveBulk(universalAuthConfig, '');
		await infisicalProvider.resolveBulk(universalAuthConfig, '');

		expect(loginCount).toBe(2);
	});

	it('surfaces a Universal Auth login failure (401) as a rejected resolveBulk', async () => {
		requestMock.mockImplementation(async (url: string) => {
			if (String(url).includes('/api/v1/auth/universal-auth/login')) {
				return response(401, {}, 'invalid client credentials');
			}
			return secretsResponse();
		});

		await expect(infisicalProvider.resolveBulk(universalAuthConfig, '')).rejects.toThrow(
			/Universal Auth login failed with HTTP 401/
		);
		// Only the login call happened; the secrets endpoint was never reached.
		expect(requestMock.mock.calls.length).toBe(1);
	});

	it('surfaces a Universal Auth login failure as ok:false from testConnection (no throw)', async () => {
		requestMock.mockImplementation(async (url: string) => {
			if (String(url).includes('/api/v1/auth/universal-auth/login')) {
				return response(401, {}, 'invalid client credentials');
			}
			return secretsResponse();
		});

		const result = await infisicalProvider.testConnection(universalAuthConfig);
		expect(result.ok).toBe(false);
		expect(result.error).toContain('401');
	});

	it('throws a clear error when the login response has no accessToken', async () => {
		requestMock.mockImplementation(async (url: string) => {
			if (String(url).includes('/api/v1/auth/universal-auth/login')) {
				return response(200, {});
			}
			return secretsResponse();
		});

		await expect(infisicalProvider.resolveBulk(universalAuthConfig, '')).rejects.toThrow(
			/did not include an accessToken/
		);
	});

	it('prefers Universal Auth over a static token when both are configured', async () => {
		requestMock.mockImplementation(async (url: string) => {
			if (String(url).includes('/api/v1/auth/universal-auth/login')) {
				return loginResponse('ua-access-token');
			}
			return secretsResponse();
		});

		await infisicalProvider.resolveBulk(
			{ ...universalAuthConfig, token: 'st.should-not-be-used' },
			''
		);
		const [, secretsOpts] = requestMock.mock.calls[1];
		expect(secretsOpts.headers.authorization).toBe('Bearer ua-access-token');
	});

	it('the static-token path never calls the login endpoint (backward compatible)', async () => {
		requestMock.mockImplementation(async () => secretsResponse());
		await infisicalProvider.resolveBulk(baseConfig, '');
		expect(requestMock.mock.calls.length).toBe(1);
		const [url, opts] = requestMock.mock.calls[0];
		expect(url).not.toContain('universal-auth');
		expect(opts.headers.authorization).toBe('Bearer st.token.value');
	});
});

describe('infisicalProvider Universal Auth config validation (no HTTP call)', () => {
	it('resolveBulk rejects when neither token nor clientId/clientSecret are set', async () => {
		const { token: _token, ...withoutToken } = baseConfig;
		await expect(infisicalProvider.resolveBulk(withoutToken, '')).rejects.toThrow(
			/Provide either an access token or a Universal Auth client ID and client secret/
		);
		expect(requestMock).not.toHaveBeenCalled();
	});

	it('resolveBulk rejects when clientId is set without clientSecret', async () => {
		const { token: _token, ...withoutToken } = baseConfig;
		await expect(
			infisicalProvider.resolveBulk({ ...withoutToken, clientId: 'client-abc' }, '')
		).rejects.toThrow(/Client secret is required/);
		expect(requestMock).not.toHaveBeenCalled();
	});

	it('resolveBulk rejects when clientSecret is set without clientId', async () => {
		const { token: _token, ...withoutToken } = baseConfig;
		await expect(
			infisicalProvider.resolveBulk({ ...withoutToken, clientSecret: 'secret-xyz' }, '')
		).rejects.toThrow(/Client ID is required/);
		expect(requestMock).not.toHaveBeenCalled();
	});

	it('testConnection returns ok:false when neither auth shape is complete', async () => {
		const { token: _token, ...withoutToken } = baseConfig;
		const result = await infisicalProvider.testConnection({
			...withoutToken,
			clientId: 'client-abc'
		});
		expect(result.ok).toBe(false);
		expect(result.error).toContain('Client secret is required');
		expect(requestMock).not.toHaveBeenCalled();
	});
});
