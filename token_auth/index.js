const uuid = require("uuid");
const express = require("express");
const onFinished = require("on-finished");
const bodyParser = require("body-parser");
const path = require("path");
const port = 3000;
const fs = require("fs");
const request = require("request");
const axios = require("axios");
const { verify } = require("./verify");

const DOMAIN = process.env.DOMAIN;
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const AUDIENCE = process.env.AUDIENCE;
const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

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

app.get("/", async (req, res) => {
  const token = req.session.access_token;
  if (token) {
    try {
      verify(token);
    } catch (error) {
      console.error(error);
    }
    const tokenLifetime =
      req.session.expires_at - Math.floor(Date.now() / 1000);
    console.log("token expires at " + tokenLifetime);
    if (tokenLifetime <= 10) {
      console.log("started refreshing token");
      const response = await refreshToken(req.session.refresh_token);
      const parsed = JSON.parse(response);
      req.session.access_token = parsed.access_token;
      req.session.expires_at =
        Math.floor(Date.now() / 1000) + parsed.expires_at;
      console.log("new token:" + parsed.access_token);
    }

    return res.json({
      username: req.session.username,
      logout: "http://localhost:3000/logout",
    });
  }
  res.sendFile(path.join(__dirname + "/index.html"));
});

app.get("/logout", (req, res) => {
  sessions.destroy(req, res);
  res.redirect("/");
});

app.post("/api/login", (req, res) => {
  const { login, password } = req.body;
  const options = {
    method: "POST",
    url: `https://${DOMAIN}/oauth/token`,
    headers: { "content-type": "application/x-www-form-urlencoded" },
    form: {
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      audience: AUDIENCE,
      grant_type: "password",
      username: login,
      password: password,
      scope: "offline_access",
    },
  };
  request(options, (error, response, body) => {
    if (error) {
      console.error(error);
    }
    const obj = JSON.parse(body);
    console.log(obj);
    req.session.username = login;
    req.session.login = login;
    req.session.access_token = obj.access_token;
    req.session.expires_at = Math.floor(Date.now() / 1000) + obj.expires_in;
    req.session.refresh_token = obj.refresh_token;
    res.json({ token: req.sessionId });
  });
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
