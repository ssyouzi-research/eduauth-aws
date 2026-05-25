import { createRemoteJWKSet, jwtVerify } from 'jose';
import { STSClient, AssumeRoleCommand } from "@aws-sdk/client-sts";

const client = new STSClient({
    region: process.env.AWS_REGION
});

const ROLE_ARN = process.env.ROLE_ARN;
const JWKS = createRemoteJWKSet(
    new URL(process.env.JWKS_URL)
);

const issuer = process.env.ISSUER;
const audience = process.env.AUDIENCE;
const domain = process.env.DOMAIN;

async function verifyOidcToken(token) {
    try {
        const { payload } = await jwtVerify(token, JWKS, {
            'issuer': issuer,
            'audience': audience
        });
        return payload;
    } catch (error) {
        console.error('Token verification failed:', error);
        return false;
    }
}

function getPayload(isBase64Encoded, body) {
    if (!isBase64Encoded) {
        return body;
    }
    return (Buffer.from(body, 'base64')).toString('utf8');
}

async function getCredentials(verified) {
    const targetLinkUri = verified['https://purl.imsglobal.org/spec/lti/claim/target_link_uri'];
    const custom = verified['https://purl.imsglobal.org/spec/lti/claim/custom'];
    const roles = verified['https://purl.imsglobal.org/spec/lti/claim/roles'];
    const context = verified['https://purl.imsglobal.org/spec/lti/claim/context'];
    const email = verified.email;
    const userId = verified.sub;

    const safeRoles = roles.map(url => url.replace('#', '_'));
    const command = new AssumeRoleCommand({
        'RoleArn': ROLE_ARN,
        'RoleSessionName': email,

        'Tags': [
            { Key: "Roles", Value: safeRoles.join(' ') },
            { Key: "UserId", Value: userId }
        ]
    });
    console.log(JSON.stringify(command));
    const response = await client.send(command);
    console.log(JSON.stringify(response));
    return response;
}

export const handler = async (event) => {
    console.log(JSON.stringify(event));
    const body = event.body;
    const isBase64Encoded = event.isBase64Encoded;
    const payload = getPayload(isBase64Encoded, body);
    const searchParams = new URLSearchParams(payload);
    console.log(JSON.stringify(Object.fromEntries(searchParams)));
    if (!searchParams.has('id_token') || !searchParams.has('state')) {
        return {
            'statusCode': 403
        };
    }
    const token = searchParams.get('id_token');

    const verified = await verifyOidcToken(token);
    console.log(JSON.stringify(verified));

    const roleCredentials = await getCredentials(verified);
    const credentials = {
        'sessionId': roleCredentials.Credentials.AccessKeyId,
        'sessionKey': roleCredentials.Credentials.SecretAccessKey,
        'sessionToken': roleCredentials.Credentials.SessionToken
    };

    const req = "https://signin.aws.amazon.com/federation" +
        "?Action=getSigninToken" +
        // "&SessionDuration=43200" +
        "&Session=" + encodeURIComponent(JSON.stringify(credentials));
    console.log(req);
    const res = await fetch(req);
    const text = await res.text();
    console.log(text);
    const signinToken = JSON.parse(text)['SigninToken'];
    const distination = encodeURIComponent('https://console.aws.amazon.com');
    return {
        statusCode: 302,
        statusDescription: 'Found',
        headers: {
            'location': `https://signin.aws.amazon.com/federation?Action=login&Issuer=${domain}&Destination=${distination}&SigninToken=${signinToken}`
        }
    };
};
