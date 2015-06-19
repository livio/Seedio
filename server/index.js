var config = require("./config/"),
    crave = require('crave'),
    express = require('express'),
    compress = require('compression'),
    passport = require('passport'),
    session = require('express-session'),
    bodyParser = require('body-parser'),
    mongoose = require('mongoose'),
    i18n = require('i18next'),
    path = require('path');

var log = new (require('seedio-log'))({mongoose: mongoose, debug: config.debug, trace: config.trace, error: config.error, name: config.name}),
    database = new (require('./libs/database/'))(config, log),
    oauth2 = new (require('./libs/oauth2/'))(config, log),
    responseHandler = new (require('seedio-response'))(config, log),
    MongoStore = require('connect-mongo')(session);

// Initialize internationalization options.
i18n.init(config.i18n);

// Create an express application object.
var app = module.exports = express();

// If the cookie is secure and proxy is enabled. We need to enable express' trust proxy for it set cookies correctly.
if(config.session.cookie.secure && config.session.proxy) {
  app.enable('trust proxy');
}

// Disable the "X-Powered-By: Express" HTTP header, which is enabled by default.
app.disable("x-powered-by");

// Log all incoming requests.
if(config.server.requests) {
  app.use(log.requestLogger());
}

// Enable G-ZIP compression.
app.use(compress());

// Parse url encoded json, "Content-Type: application/x-www-form-urlencoded"
app.use(bodyParser.urlencoded({ extended: false}));

// Parse bodies with json, "Content-Type: application/json"
app.use(bodyParser.json());

// Adds i18n object to req object
app.use(i18n.handle);

// TODO: Set-up Views engines
app.set('view engine', null);
//app.set('views','../client/views');
//app.set('view engine', 'jade');

// Make public folder static so it can be served
app.use(express.static('../client/public', config.express.static));

// Extend express response object.
app.use(responseHandler.addSetMethods);

// Allows use of the translate function inside of a Jade template.
i18n.registerAppHelper(app);

// Configure express sessions
app.use(session({
  name: config.session.name,
  secret: config.session.secret,
  cookie: {
    secure: config.session.cookie.secure
  },
  resave: config.session.resave,
  saveUninitialized: config.session.saveUninitialized,
  store: new MongoStore({
    url: config.database.uri,
    ttl: config.session.cookie.ttl
  })
}));
app.use(passport.initialize());
app.use(passport.session());

// Method to connect to database and start the server.
var start = function(err) {
  if(err) {
    return log.e(err);
  }

  database.connect(function(err) {
    if(err) {
      return log.e(err);
    }

    oauth2.createOauth2Server(app, config, log, function(err) {
      if(err) {
        return log.e(err);
      }
    });

    // Final middleware to format standard responses.
    app.use(responseHandler.responseHandler(function(req, res, next) {
      // TODO: Add any logic needed to handle a view not being found.
      next();
    }));

    // Final middleware to format any error responses.
    app.use(responseHandler.errorHandler(function(err, req, res, next) {
      // TODO: Add any logic needed to render error views.
      next();
    }));

    var server = app.listen(config.server.port, function() {
      var serverInfo = this.address();
      var address = (serverInfo.address === "0.0.0.0" || serverInfo.address === "::") ? "localhost" : serverInfo.address;

      log.i("Listening on http://%s:%s with database %s", address, serverInfo.port, config.database.uri.replace(/mongodb:\/\/(.*:.*)@/ig, ''));
    });
  });
};

// Configure Crave.
crave.setConfig(config.crave);

// Recursively load all files of the specified type(s) that are also located in the specified folder.
crave.directory(path.resolve("./app"), [ "model", "authentication", "controller" ], start, app, config, log, oauth2);
