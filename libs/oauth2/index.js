/**
 * Module dependencies.
 */
var BasicStrategy = require('passport-http').BasicStrategy,
    BearerStrategy = require('passport-http-bearer').Strategy,
    ClientPasswordStrategy = require('passport-oauth2-client-password').Strategy,
    db = require('mongoose'),
    login = require('connect-ensure-login'),
    oauth2orize = require('oauth2orize'),
    passport = require('passport'),
    Response = require('seedio-response');
    url = require('url');

var User, AuthorizationCode, AccessToken, SdlServer;

var config, log, response, server;

var authorization, decision, token, ensureLoggedInApi;

var Oauth2 = function(_config, _log) {
  config = _config;
  log = _log;

  response = new Response(config, log);

  setupPassport();
};

var createOauth2Server = function(app, config, log, cb) {

  User = db.model("User");
  AuthorizationCode = db.model("AuthorizationCode");
  AccessToken = db.model("AccessToken");

  server = oauth2orize.createServer();

  // Register serialialization and deserialization functions.
//
// When a client redirects a user to user authorization endpoint, an
// authorization transaction is initiated.  To complete the transaction, the
// user must authenticate and approve the authorization request.  Because this
// may involve multiple HTTP request/response exchanges, the transaction is
// stored in the session.
//
// An application must supply serialization functions, which determine how the
// client object is serialized into the session.  Typically this will be a
// simple matter of serializing the client's ID, and deserializing by finding
// the client by ID from the database.
  server.serializeClient(function(sdlServer, done) {
    console.log("SerializeClient(): %s", JSON.stringify(sdlServer, undefined, 2));
    return done(null, sdlServer._id);
  });

  server.deserializeClient(function(id, done) {
    console.log("DeserializeClient(): %s", id);
    SdlServer.findById(id, function(err, sdlServer) {
      if (err) {
        return done(err);
      }
      return done(null, sdlServer);
    });
  });


  // Register supported grant types.
  //
  // OAuth 2.0 specifies a framework that allows users to grant client
  // applications limited access to their protected resources.  It does this
  // through a process of the user granting access, and the client exchanging
  // the grant for an access token.

  // Grant authorization codes.  The callback takes the `client` requesting
  // authorization, the `redirectURI` (which is used as a verifier in the
  // subsequent exchange), the authenticated `user` granting access, and
  // their response, which contains approved scope, duration, etc. as parsed by
  // the application.  The application issues a code, which is bound to these
  // values, and will be exchanged for an access token.
  server.grant(oauth2orize.grant.code(function(client, redirectUri, user, ares, done) {
    console.log("Grant Code():\nclient:  %s\nuri:  %s\nuser:  %s\n", JSON.stringify(client, undefined, 2), redirectUri, JSON.stringify(user, undefined, 2));
    var code = new AuthorizationCode();

    code.update({ client: client._id, redirectUri: redirectUri, user: user._id}, undefined, function(err) {
      if (err) {
        return done(err);
      }

      console.log("CODE: ");
      console.log(code);

      done(null, code.code);
    });
  }));

  // Grant implicit authorization.  The callback takes the `client` requesting
  // authorization, the authenticated `user` granting access, and
  // their response, which contains approved scope, duration, etc. as parsed by
  // the application.  The application issues a token, which is bound to these
  // values.
  server.grant(oauth2orize.grant.token(function(client, user, ares, done) {
    console.log("Grant Token():\nclient:  %s\ntoken:  %s", JSON.stringify(client, undefined, 2), JSON.stringify(user, undefined, 2));
    var token = new AccessToken();
    AccessToken.update({ user: user._id, client: client._id }, undefined, function(err) {  // is this correct?
      if (err) { return done(err); }
      done(null, token);
    });
  }));

  // Exchange authorization codes for access tokens.  The callback accepts the
  // `client`, which is exchanging `code` and any `redirectURI` from the
  // authorization request for verification.  If these values are validated, the
  // application issues an access token on behalf of the user who authorized the
  // code.
  server.exchange(oauth2orize.exchange.code(function(client, code, redirectUri, done) {
    console.log("Exchange Code for Token():\nclient:  %s\ncode:  %s\nredirectUri:  %s", JSON.stringify(client, undefined, 2), code, redirectUri);
    AuthorizationCode.findByCode(code, function(err, authCode) {
      if (err) {
        return done(err);
      }

      console.log("Auth Code: %s", JSON.stringify(authCode, undefined, 2));

      if(authCode.client === undefined) {
        console.log("Client ID is not defined in the authorization code.");
        return done(null, false);
      }

      if (client._id.toString() != authCode.client.toString()) {
        console.log("Client IDs do not match: %s != %s", client._id.toString(), authCode.client.toString());
        return done(null, false);
      }

      if( ! authCode.verifyRedirectUri(redirectUri)) {
        console.log("Redirect URI does not match: %s != %s", redirectUri, authCode.redirectUri);
        return done(null, false);
      }

      var token = new AccessToken();
      token.update({ client: authCode.client, user: authCode.user }, undefined, function(err, token) {
        if (err) {
          return done(err);
        }

        authCode.remove(function(err) {
          if(err) {
            console.log(err);
          }
          done(null, token.token);
        });
      });
    });
  }));

  // Exchange user id and password for access tokens.  The callback accepts the
  // `client`, which is exchanging the user's name and password from the
  // authorization request for verification. If these values are validated, the
  // application issues an access token on behalf of the user who authorized the code.
  server.exchange(oauth2orize.exchange.password(function(client, username, password, scope, done) {
    console.log("Exchange Username/password for Token():\nclient:  %s\nusername:  %s\npassword:  %s", JSON.stringify(client, undefined, 2), username, password);
    /*  TODO:  Make this use sdl server.
     Client.findByClientIdentifier(client.clientId, function(err, localClient) {
     if (err) {
     return done(err);
     }

     if(localClient === null) {
     return done(null, false);
     }

     if(localClient.clientSecret !== client.clientSecret) {
     return done(null, false);
     }

     //Validate the user
     User.findByUsername(username, function(err, user) {
     if (err) {
     return done(err);
     }

     if(user === null) {
     return done(null, false);
     }

     if( ! user.authenticate(password)) {
     return done(null, false);
     }

     var token = new AccessToken();
     token.update({ client: client._id, user: user._id }, undefined, function(err) {
     if (err) { return done(err); }
     done(null, token);
     });
     });
     });
     */
  }));

  // Exchange the client id and password/secret for an access token.  The callback accepts the
  // `client`, which is exchanging the client's id and password/secret from the
  // authorization request for verification. If these values are validated, the
  // application issues an access token on behalf of the client who authorized the code.
  server.exchange(oauth2orize.exchange.clientCredentials(function(client, scope, done) {
    console.log("Exchange Client ID and Password/Secret for Token():\nclient:  %s\nscope:  %s", JSON.stringify(client, undefined, 2), scope);

    /* TODO: Use SDL Server instead of client.
     Client.findByClientIdentifier(client.clientId, function(err, localClient) {
     if (err) {
     return done(err);
     }

     if(localClient === null) {
     return done(null, false);
     }

     if(localClient.clientSecret !== client.clientSecret) {
     return done(null, false);
     }

     var token = new AccessToken();
     token.update({ client: client._id }, undefined, function(err) {
     if (err) { return done(err); }
     done(null, token);
     });
     });
     */
  }));

  // user authorization endpoint
  //
  // `authorization` middleware accepts a `validate` callback which is
  // responsible for validating the client making the authorization request.  In
  // doing so, is recommended that the `redirectURI` be checked against a
  // registered value, although security requirements may vary across
  // implementations.  Once validated, the `done` callback must be invoked with
  // a `client` instance, as well as the `redirectURI` to which the user will be
  // redirected after an authorization decision is obtained.
  //
  // This middleware simply initializes a new authorization transaction.  It is
  // the application's responsibility to authenticate the user and render a dialog
  // to obtain their approval (displaying details about the client requesting
  // authorization).  We accomplish that here by routing through `ensureLoggedIn()`
  // first, and rendering the `dialog` view.
  authorization = [
    login.ensureLoggedIn(),
    server.authorization(function(clientId, redirectUri, done) {
      console.log("oauth 2.0 authorization:\n\tclientId:  %s\n\tredirectUri:  %s", clientId, redirectUri);
      SdlServer.findByOauth2Identifier(clientId, function(err, sdlServer) {
        if (err) {
          return done(err);
        }

        if( ! sdlServer.verifyOauth2RedirectUri(redirectUri)) {
          return done(new Error("Invalid redirect URI of " + redirectUri));
        }

        return done(null, sdlServer, redirectUri);
      });
    }),
    function(req, res) {
      console.log("oauth 2.0 authorization:\n\ttransactionID:  %s\n\tuserId: %s", req.oauth2.transactionID, req.user._id);
      //res.render('permission', { transactionID: req.oauth2.transactionID, user: req.user, client: req.oauth2.client });
    }
  ];

  // user decision endpoint
//
// `decision` middleware processes a user's decision to allow or deny access
// requested by a client application.  Based on the grant type requested by the
// client, the above grant middleware configured above will be invoked to send
// a response.
  decision = [
    login.ensureLoggedIn(),
    server.decision()
  ];

  // token endpoint
  //
  // `token` middleware handles client requests to exchange authorization grants
  // for access tokens.  Based on the grant type being exchanged, the above
  // exchange middleware will be invoked to handle the request.  Clients must
  // authenticate when making requests to this endpoint.
  token = [
    passport.authenticate(['oauth2-client-password'], { session: false }),
    server.token(),
    server.errorHandler()
  ];


  var oauth2 = {
    "authorization": authorization,
    "decision": decision,
    "token": token,
    "ensureLoggedInApi": ensureLoggedInApi
  };


  var controller = require('./controller.js')(app, config, log, oauth2);

  cb();
};

var setupPassport = function() {
  passport.use(new BasicStrategy(
    function (clientId, clientSecret, done) {
      db.model("SdlServer").findOne({ "oauth2Identifier": clientId }, function(err, sdlServer) {
        if (err) {
          return done(err);
        }

        if ( ! sdlServer) {
          console.log("server not found.");
          return done(null, false);
        }

        if (sdlServer.oauth2Secret != clientSecret) {
          console.log("Secret doesn't match");
          return done(null, false);
        }

        console.log("server returned: %s", JSON.stringify(sdlServer, undefined, 2));
        return done(null, sdlServer);
      });
    }
  ));

  passport.use(new ClientPasswordStrategy(
    function(clientId, clientSecret, done) {
      console.log("Client Password Strategy");
      db.model("SdlServer").findOne({ "oauth2Identifier": clientId }, function(err, sdlServer) {
        if (err) {
          return done(err);
        }

        if ( ! sdlServer) {
          console.log("server not found.");
          return done(null, false);
        }

        if (sdlServer.oauth2Secret != clientSecret) {
          console.log("Secret doesn't match");
          return done(null, false);
        }

        console.log("server returned: %s", JSON.stringify(sdlServer, undefined, 2));
        return done(null, sdlServer);
      });
    }
  ));


  passport.use(new BearerStrategy({ passReqToCallback: true },function(req, token, next) {
    AccessToken.findOne({ token: token}).populate('user').exec(function(err, accessToken) {
      if(err) {
        log.trace('BearerStrategy(): Error occurred with token %s ', token);
        log.trace(err);
        next(err);
      } else if( ! accessToken) {
        log.trace('BearerStrategy(): Access token is not authorized: %s ', token);
        next(response.createUnauthorizedError(req), false);
      } else {
        User.populate(accessToken.user, { path: 'roles' }, function(err, user) {
          if( ! user.roles || user.roles.length == 0) {
            log.trace("BearerStrategy(): User %s does not have any roles: %s", user._id, JSON.stringify(user.roles, undefined,2));
          }
          next(err, user, {scope: 'all'});
        });
      }
    });
  }));
};


Oauth2.prototype.ensureLoggedIn = function(req, res, next) {
  login.ensureLoggedIn.apply(null, _arguments)(req, res, next);
};

/**
 * Returns a method that will ensure a user is authenticated
 * before proceeding.  If the user is using an access token,
 * then the Bearer strategy will be used.  If the user is not
 * using a token, then the basic local strategy will be used.
 *
 * This method accepts any parameter you can pass to the ensureLoggedIn method.
 * @returns {Function}
 */
Oauth2.prototype.ensureLoggedInApi = function() {
  var _arguments = arguments;

  return function(req, res, next) {
    if(req.query.access_token) {
      passport.authenticate('bearer', { session: false })(req, res, next);
    } else {
      login.ensureLoggedIn.apply(null, _arguments)(req, res, next);
    }
  }
};

/**
 * Returns a method that will check if a user is authenticated
 * before proceeding, but will not stop an unauthenticated user
 * from proceeding.  If the user is using an access token, then
 * the Bearer strategy will be used.  If the user is not using
 * a token, then the basic local strategy will be used.
 *
 * This method accepts any parameter you can pass to the ensureLoggedIn method.
 * @returns {Function}
 */
Oauth2.prototype.checkLoggedInApi = function() {
  var _arguments = arguments;

  return [
    function(req, res, next) {
      if(req.query.access_token) {
        passport.authenticate('bearer', { session: false })(req, res, next);
      } else {
        req.user = req._passport.session.user;
        next();
        //login.ensureLoggedIn.apply(null, _arguments)(req, res, next);
      }
    },
    function(err, req, res, next) {
      // Clear any errors.
      next();
    }
  ];
};



Oauth2.prototype.createOauth2Server = createOauth2Server;
Oauth2.prototype.authorization = authorization;
Oauth2.prototype.decision = decision;
Oauth2.prototype.token = token;

exports = module.exports = Oauth2;
exports = Oauth2;