/**
 * List of supported OAuth providers.
 */
const supportedProviders = ['github', 'gitlab'];

/**
 * Escape the given string for safe use in a regular expression.
 * @param {string} str - Original string.
 * @returns {string} Escaped string.
 * @see https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_expressions#escaping
 */
const escapeRegExp = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Helper functions for JWT generation for GitHub Apps.
 * These functions generate a JWT using RS256 and your private key.
 */

async function importPrivateKey(pemKey) {
  // Remove header, footer, and whitespace from PEM
  const pemContents = pemKey
    .replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/\s/g, '');
  const binaryDer = Uint8Array.from(atob(pemContents), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey(
    "pkcs8",
    binaryDer.buffer,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
    false,
    ["sign"]
  );
}

async function signToken(unsignedToken, pemKey) {
  const key = await importPrivateKey(pemKey);
  const encoder = new TextEncoder();
  const data = encoder.encode(unsignedToken);
  const signature = await crypto.subtle.sign(
    {
      name: "RSASSA-PKCS1-v1_5",
    },
    key,
    data
  );
  // Convert signature to base64url
  let binary = '';
  const bytes = new Uint8Array(signature);
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64Signature = btoa(binary);
  return base64Signature.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function generateJWT(appId, privateKey) {
  const header = { alg: "RS256", typ: "JWT" };
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + 600; // Expires in 10 minutes
  const payload = { iat, exp, iss: appId };
  const encode = (obj) =>
    btoa(JSON.stringify(obj))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  const unsignedToken = `${encode(header)}.${encode(payload)}`;
  const signature = await signToken(unsignedToken, privateKey);
  return `${unsignedToken}.${signature}`;
}

/**
 * Output HTML response that communicates with the window opener.
 * @param {object} args - Options.
 * @param {string} [args.provider] - Backend name, e.g. `github`.
 * @param {string} [args.token] - OAuth token.
 * @param {string} [args.error] - Error message when a token is not available.
 * @param {string} [args.errorCode] - Error code to be used for localization.
 * @returns {Response} Response with HTML.
 */
const outputHTML = ({ provider = 'unknown', token, error, errorCode }) => {
  const state = error ? 'error' : 'success';
  const content = error ? { provider, error, errorCode } : { provider, token };

  return new Response(
    `
      <!doctype html><html><body><script>
        (() => {
          window.addEventListener('message', ({ data, origin }) => {
            if (data === 'authorizing:${provider}') {
              window.opener?.postMessage(
                'authorization:${provider}:${state}:${JSON.stringify(content)}',
                origin
              );
            }
          });
          window.opener?.postMessage('authorizing:${provider}', '*');
        })();
      </script></body></html>
    `,
    {
      headers: {
        'Content-Type': 'text/html;charset=UTF-8',
        // Delete CSRF token
        'Set-Cookie': `csrf-token=deleted; HttpOnly; Max-Age=0; Path=/; SameSite=Lax; Secure`,
      },
    }
  );
};

/**
 * Handle the `auth` method, the first step in the authorization flow.
 * @param {Request} request - HTTP request.
 * @param {{ [key: string]: string }} env - Environment variables.
 * @returns {Promise<Response>} HTTP response.
 */
const handleAuth = async (request, env) => {
  const { url } = request;
  const { origin, searchParams } = new URL(url);
  const { provider, site_id: domain } = Object.fromEntries(searchParams);

  if (!provider || !supportedProviders.includes(provider)) {
    return outputHTML({
      error: 'Your Git backend is not supported by the authenticator.',
      errorCode: 'UNSUPPORTED_BACKEND',
    });
  }

  const {
    ALLOWED_DOMAINS,
    // GitHub App variables
    GITHUB_APP_SLUG,
    GITHUB_APP_ID,
    GITHUB_PRIVATE_KEY,
    // GitLab OAuth variables
    GITLAB_CLIENT_ID,
    GITLAB_CLIENT_SECRET,
    GITLAB_HOSTNAME = 'gitlab.com',
  } = env;

  // Check if the domain is whitelisted
  if (
    ALLOWED_DOMAINS &&
    !ALLOWED_DOMAINS.split(/,/).some((str) =>
      (domain ?? '').match(new RegExp(`^${escapeRegExp(str.trim()).replace('\\*', '.+')}$`))
    )
  ) {
    return outputHTML({
      provider,
      error: 'Your domain is not allowed to use the authenticator.',
      errorCode: 'UNSUPPORTED_DOMAIN',
    });
  }

  // Generate a random string for CSRF protection
  const csrfToken = globalThis.crypto.randomUUID().replaceAll('-', '');
  let authURL = '';

  // GitHub using GitHub Apps
  if (provider === 'github') {
    if (!GITHUB_APP_SLUG || !GITHUB_APP_ID || !GITHUB_PRIVATE_KEY) {
      return outputHTML({
        provider,
        error: 'GitHub App credentials are not configured.',
        errorCode: 'MISCONFIGURED_CLIENT',
      });
    }
    // Redirect to the GitHub App installation page.
    // (Optionally, you can append a state parameter if your app supports it.)
    authURL = `https://github.com/apps/${GITHUB_APP_SLUG}/installations/new`;
  }

  // GitLab OAuth flow remains unchanged.
  if (provider === 'gitlab') {
    if (!GITLAB_CLIENT_ID || !GITLAB_CLIENT_SECRET) {
      return outputHTML({
        provider,
        error: 'OAuth app client ID or secret is not configured.',
        errorCode: 'MISCONFIGURED_CLIENT',
      });
    }

    const params = new URLSearchParams({
      client_id: GITLAB_CLIENT_ID,
      redirect_uri: `${origin}/callback`,
      response_type: 'code',
      scope: 'api',
      state: csrfToken,
    });

    authURL = `https://${GITLAB_HOSTNAME}/oauth/authorize?${params.toString()}`;
  }

  // Set CSRF token in cookie and redirect.
  return new Response('', {
    status: 302,
    headers: {
      Location: authURL,
      'Set-Cookie':
        `csrf-token=${provider}_${csrfToken}; HttpOnly; Path=/; Max-Age=600; SameSite=Lax; Secure`,
    },
  });
};

/**
 * Handle the `callback` method, the second step in the authorization flow.
 * @param {Request} request - HTTP request.
 * @param {{ [key: string]: string }} env - Environment variables.
 * @returns {Promise<Response>} HTTP response.
 */
const handleCallback = async (request, env) => {
  const { url, headers } = request;
  const { origin, searchParams } = new URL(url);
  // For GitLab OAuth, we expect a code and state.
  const { code, state } = Object.fromEntries(searchParams);

  // Extract provider and CSRF token from cookie.
  const [, provider, csrfToken] =
    headers.get('Cookie')?.match(/\bcsrf-token=([a-z-]+?)_([0-9a-f]{32})\b/) ?? [];

  if (!provider || !supportedProviders.includes(provider)) {
    return outputHTML({
      error: 'Your Git backend is not supported by the authenticator.',
      errorCode: 'UNSUPPORTED_BACKEND',
    });
  }

  let token = '';
  let error = '';
  let response;

  if (provider === 'github') {
    // For GitHub Apps, expect an installation_id parameter instead of a code.
    const { installation_id } = Object.fromEntries(searchParams);
    if (!installation_id) {
      return outputHTML({
        provider,
        error: 'Missing installation ID in callback.',
        errorCode: 'MISSING_INSTALLATION_ID',
      });
    }
    const { GITHUB_APP_ID, GITHUB_PRIVATE_KEY } = env;
    if (!GITHUB_APP_ID || !GITHUB_PRIVATE_KEY) {
      return outputHTML({
        provider,
        error: 'GitHub App credentials are not configured.',
        errorCode: 'MISCONFIGURED_CLIENT',
      });
    }
    // Generate a JWT for GitHub App authentication.
    const jwtToken = await generateJWT(GITHUB_APP_ID, GITHUB_PRIVATE_KEY);
    // Exchange the JWT for an installation access token.
    const tokenURL = `https://api.github.com/app/installations/${installation_id}/access_tokens`;
    try {
      response = await fetch(tokenURL, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${jwtToken}`,
          Accept: 'application/vnd.github.v3+json'
        }
      });
      const data = await response.json();
      token = data.token;
      error = data.error;
    } catch (err) {
      return outputHTML({
        provider,
        error: 'Failed to request an installation access token. Please try again later.',
        errorCode: 'TOKEN_REQUEST_FAILED',
      });
    }
  }

  if (provider === 'gitlab') {
    if (!code || !state) {
      return outputHTML({
        provider,
        error: 'Failed to receive an authorization code. Please try again later.',
        errorCode: 'AUTH_CODE_REQUEST_FAILED',
      });
    }
    if (!csrfToken || state !== csrfToken) {
      return outputHTML({
        provider,
        error: 'Potential CSRF attack detected. Authentication flow aborted.',
        errorCode: 'CSRF_DETECTED',
      });
    }
    const { GITLAB_CLIENT_ID, GITLAB_CLIENT_SECRET, GITLAB_HOSTNAME = 'gitlab.com' } = env;
    if (!GITLAB_CLIENT_ID || !GITLAB_CLIENT_SECRET) {
      return outputHTML({
        provider,
        error: 'OAuth app client ID or secret is not configured.',
        errorCode: 'MISCONFIGURED_CLIENT',
      });
    }
    const tokenURL = `https://${GITLAB_HOSTNAME}/oauth/token`;
    const requestBody = {
      code,
      client_id: GITLAB_CLIENT_ID,
      client_secret: GITLAB_CLIENT_SECRET,
      grant_type: 'authorization_code',
      redirect_uri: `${origin}/callback`,
    };
    try {
      response = await fetch(tokenURL, {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestBody),
      });
      const data = await response.json();
      token = data.access_token;
      error = data.error;
    } catch {
      return outputHTML({
        provider,
        error: 'Failed to request an access token. Please try again later.',
        errorCode: 'TOKEN_REQUEST_FAILED',
      });
    }
  }

  return outputHTML({ provider, token, error });
};

export default {
  /**
   * Main request handler.
   * @param {Request} request - HTTP request.
   * @param {{ [key: string]: string }} env - Environment variables.
   * @returns {Promise<Response>} HTTP response.
   */
  async fetch(request, env) {
    const { method, url } = request;
    const { pathname } = new URL(url);

    if (method === 'GET' && ['/auth', '/oauth/authorize'].includes(pathname)) {
      return handleAuth(request, env);
    }

    if (method === 'GET' && ['/callback', '/oauth/redirect'].includes(pathname)) {
      return handleCallback(request, env);
    }

    return new Response('', { status: 404 });
  },
};
