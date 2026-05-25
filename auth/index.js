const AUTH = process.env.AUTH_URL;
const callback = process.env.REDIRECT_URI;

function getPayload(isBase64Encoded, body) {
    if (!isBase64Encoded) {
        return body;
    }
    return (Buffer.from(body, 'base64')).toString('utf8');
}

export const handler = async (event) => {
    // console.log(JSON.stringify(event));
    const body = event.body;
    const isBase64Encoded = event.isBase64Encoded;
    const payload = getPayload(isBase64Encoded, body);
    const searchParams = new URLSearchParams(payload);
    console.log(JSON.stringify(Object.fromEntries(searchParams)));

    const state = crypto.randomUUID();
    const nonce = crypto.randomUUID();
    
    const authParams = new URLSearchParams();
    authParams.append('scope', 'openid');
    authParams.append('response_type', 'id_token');
    authParams.append('client_id', searchParams.get('client_id'));
    authParams.append('redirect_uri', callback);
    authParams.append('login_hint', searchParams.get('login_hint'));
    authParams.append('response_mode', 'form_post');
    authParams.append('state', state);
    authParams.append('nonce', nonce);
    authParams.append('prompt', 'none');
    if (searchParams.has('lti_message_hint')) {
        authParams.append('lti_message_hint', searchParams.get('lti_message_hint'));
    }
    const authUrl = `${AUTH}?${authParams.toString()}`;
    console.log(authUrl);

    return {
      statusCode: 302,
      statusDescription: 'Found',
      headers: {
        'location': authUrl
      },
    };
};
