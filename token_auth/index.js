const uuid = require("uuid");
const express = require("express");
const onFinished = require("on-finished");
const bodyParser = require("body-parser");
const port = 3000;
const path = require("path");
const fs = require("fs");
const request = require("request");
const axios = require("axios");
const { redirectUri, getAccessTokensFromCode } = require("./auth0");

const DOMAIN = process.env.DOMAIN;
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const AUDIENCE = process.env.AUDIENCE;
const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "GET,POST,DELETE");
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested With, Content-Type, Accept"
  );
  next();
});
const SESSION_KEY = "Authorization";

class Session {
  #sessions = {};

  constructor() {
    try {
      this.#sessions = fs.readFileSync("./sessions.json", "utf8");
      this.#sessions = JSON.parse(this.#sessions.trim());

      console.log(this.#sessions);
    } catch (e) {
      this.#sessions = {};
    }
  }

  #storeSessions() {
    fs.writeFileSync(
      "./sessions.json",
      JSON.stringify(this.#sessions),
      "utf-8"
    );
  }

  set(key, value) {
    if (!value) {
      value = {};
    }
    this.#sessions[key] = value;
    this.#storeSessions();
  }

  get(key) {
    return this.#sessions[key];
  }

  init(res) {
    const sessionId = uuid.v4();
    this.set(sessionId);

    return sessionId;
  }

  destroy(req, res) {
    const sessionId = req.sessionId;
    delete this.#sessions[sessionId];
    this.#storeSessions();
  }
}
const sessions = new Session();

app.use((req, res, next) => {
  let currentSession = {};
  let sessionId = req.get(SESSION_KEY);

  if (sessionId) {
    currentSession = sessions.get(sessionId);
    if (!currentSession) {
      currentSession = {};
      sessionId = sessions.init(res);
    }
  } else {
    sessionId = sessions.init(res);
  }

  req.session = currentSession;
  req.sessionId = sessionId;

  onFinished(req, () => {
    const currentSession = req.session;
    const sessionId = req.sessionId;
    sessions.set(sessionId, currentSession);
  });

  next();
});

const refreshToken = (refreshToken) => {
  return new Promise((resolve, reject) => {
    const options = {
      method: "POST",
      url: `https://${DOMAIN}/oauth/token`,
      headers: {
        "content-type": "application/x-www-form-urlencoded",
      },
      form: {
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        grant_type: "refresh_token",
        refresh_token: refreshToken,
      },
    };

    request(options, (error, response, body) => {
      if (error) reject(error);
      resolve(body);
    });
  });
};

app.get("/", (req, res) => {
  if (req.session?.username) {
    return res.json({
      username: req.session.username,
      logout: "http://localhost:3000/logout",
    });
  }

  res.sendFile(path.join(__dirname + "/index.html"));
});

app.get("/logout", (req, res) => {
  sessions.destroy(req, res);
  res.clearCookie("refresh_token", {
    httpOnly: true,
    secure: false,
    domain: "localhost",
    path: "/",
  });
  res.clearCookie("access_token", {
    httpOnly: true,
    secure: false,
    domain: "localhost",
    path: "/",
  });
  res.status(204).send();
});

app.post("/api/login", async (req, res) => {
  const redirectUrl = redirectUri();
  res.json({ redirectUrl });
});

app.get("/oidc-callback", async (req, res) => {
  const tokens = await getAccessTokensFromCode(req.query.code);

  if (tokens) {
    res.cookie("refresh_token", tokens.refresh_token, {
      httpOnly: true,
      secure: false,
    });
    res.cookie("access_token", tokens.access_token, {
      httpOnly: false,
      secure: false,
    });

    res.redirect("/");
  } else {
    res.status(401).send();
  }
});

const obtainToken = async () => {
  const options = {
    method: "POST",
    url: `https://${DOMAIN}/oauth/token`,
    headers: { "content-type": "application/x-www-form-urlencoded" },
    data: new URLSearchParams({
      grant_type: "client_credentials",
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      audience: AUDIENCE,
    }),
  };

  const response = await axios.request(options);
  return response.data.access_token;
};

app.post("/api/signup", async (req, res) => {
  const accessToken = await obtainToken();
  const { login, password } = req.body;
  let data = JSON.stringify({
    email: login,
    nickname: login,
    connection: "Username-Password-Authentication",
    password: password,
  });

  let config = {
    method: "post",
    maxBodyLength: Infinity,
    url: `https://${DOMAIN}/api/v2/users`,
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      Authorization: `Bearer ${accessToken}`,
    },
    data: data,
  };

  axios
    .request(config)
    .then((response) => {
      console.log(JSON.stringify(response.data));
    })
    .catch((error) => {
      console.log(error);
    });
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
