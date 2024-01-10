const axios = require("axios");
const DOMAIN="dev-z1ifr87jkdin16z0.us.auth0.com";
const CLIENT_ID = "zvwrqFH6vWOxBDlV1OKI7rrmuxtsdquV";
const AUDIENCE = "https://dev-z1ifr87jkdin16z0.us.auth0.com/api/v2/"
const AUTH0_URL = "https://" + DOMAIN + "/";
const CLIENT_SECRET = "6JIaIzA4CcGVW7dqd-Z6oKpLetRbXM54CldGjjnilRM2tvL9HVIBlZ8TTqi83YgY";

const redirectUri = () => {
  const localRedirectUri = encodeURIComponent(
    "http://localhost:3000/oidc-callback"
  );

  return `${AUTH0_URL}authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${localRedirectUri}&scope=offline_access&audience=${AUDIENCE}`;
};

const getAccessTokensFromCode = async (code) => {
  try {
    const data = {
      grant_type: "authorization_code",
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      code: code,
      audience: AUDIENCE,
      redirect_uri: "http://localhost:3000",
    };

    const authResponse = await axios.post(AUTH0_URL + "oauth/token", data, {
      headers: { "content-type": "application/x-www-form-urlencoded" },
    });

    if (authResponse.status !== 200) {
      return null;
    }
    console.log(authResponse.data);
    return {
      access_token: authResponse.data.access_token,
      refresh_token: authResponse.data.refresh_token,
    };
  } catch (error) {
    console.log(error);
    return null;
  }
};

module.exports = { redirectUri, getAccessTokensFromCode };
