import jsonwebtoken from 'jsonwebtoken'
import { createLogger } from '../../utils/logger.mjs'

const logger = createLogger('auth')

const jwksUrl = 'https://test-endpoint.auth0.com/.well-known/jwks.json'

const certificate = `-----BEGIN CERTIFICATE-----
MIIDHTCCAgWgAwIBAgIJI/g88Cc3yUyLMA0GCSqGSIb3DQEBCwUAMCwxKjAoBgNV
BAMTIWRldi14bnB6YzAwN2tjYndva2RlLnVzLmF1dGgwLmNvbTAeFw0yMzEyMDIw
OTA2NTFaFw0zNzA4MTAwOTA2NTFaMCwxKjAoBgNVBAMTIWRldi14bnB6YzAwN2tj
Yndva2RlLnVzLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBALqx6t56GsLULvHK6t9rWlrRe+iBCd6tooz9FeVJfcvGJi4cxGts2YKtIYTr
VREU4cne8gZALkCH5qlLgsD75J5+8mvzQzgWGl/fjglrWlpPZ8F6HvXebEQ5yuPP
FzOHfsB80wAfcb+Cdqnp3sgtqRwhKxQBZRbeen9c6pRCMdmo8BCf3EP41jtYZpIm
pEoiAkVMzj8la1wPVp9WTYtW5kskokX5f7MNj1+Yyy9FJSUy/WthXMwevMXoUFf0
N6TdpwMOjqRI0HtaMI/M7KraHgss7Zh0VkzDKqi8OO15YO+SX5z51axeMlc8CFHh
ayJeiNnCWfaVfJUXRDDRbfhiZdECAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAd
BgNVHQ4EFgQUN9UiQFNuCM/7j34BLK7yg6yZpiYwDgYDVR0PAQH/BAQDAgKEMA0G
CSqGSIb3DQEBCwUAA4IBAQAd278P6rq9qnXaS0fwswypcy/vTGCYpV3RuTvzpkq3
qT4qcmV9nudRGpE/1LVgG8ob8tU4o/fZDWqiXLORLH9cpxRiarsfIfnkQuIZHAcq
+7Wc+frdDNopW8iZx9cSrKtEtWqZnP5+t2F6YPmeCaKyRkcJsTin+QCwr1p1zM02
+9ePDrEWkheh8LAZsymXZdhqOT+SZA1DxnAWuJv/uP/2dNrLw0LzA3QgQ9KySUJU
TABlWlRX63pW9uAc0RS/93El3DbKJ79JlFElA7W1lA61gMDhfj1Ga6dA7ofIJV6Z
WwbgdWS4QTOfIJfEWTJSfgZwcsDzdaXuq6H8B0meDlLT
-----END CERTIFICATE-----`

export async function handler(event) {
  try {
    const jwtToken = await verifyToken(event.authorizationToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    logger.error('User not authorized', { error: e.message })

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

async function verifyToken(authHeader) {
  const token = getToken(authHeader)
  const jwt = jsonwebtoken.decode(token, { complete: true })

  // TODO: Implement token verification
  jsonwebtoken.verify(token, certificate, { algorithms: ['RS256'] })
  return jwt;
}

function getToken(authHeader) {
  if (!authHeader) throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return token
}
