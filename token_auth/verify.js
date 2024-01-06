const axios = require('axios');
const jsonwebtoken = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');

const DOMAIN = process.env.DOMAIN;

const getJwks = async () => {
  const response = await axios.get('https://' + DOMAIN + '/.well-known/jwks.json');
  if (response.status === 200) return response.data.keys[0];
};

const verify = async (token) => {
  const jwks = await getJwks();
  console.log(jwks);
  const result = jsonwebtoken.verify(token, jwkToPem(jwks));
  console.log(result);
};

module.exports = { verify };
