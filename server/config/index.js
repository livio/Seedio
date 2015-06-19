var path = require('path');

var Config = function() {

  // Information about the administrator of the server.
  this.admin = {
    // Email address used for notifications.
    email: ""
  };

  // Settings for the server's database connection.
  this.database = {
    initializeOnConnect: true,
    uri: "mongodb://localhost:27017/seedio_local"  // URI used to connect to the Mongo DB datastore.
  };

  // Crave is a module used to find and require files dynamically.
  this.crave = {
    cache: {
      enable: false             // Disable caching of the list of files to load.  In production this should be enabled.
    },
    identification: {           // Variables related to how to find and require files are stored here.
      type: "filename",         // Determines how to find files.  Available options are: 'string', 'filename'
      identifier: "_"           // Determines how to identify the files.
    }
  };

  this.crypto = {
    // Choose iterations to satisfy the formula v-2^(n-1) > f-p  source:  http://goo.gl/tPVs1M
    iterations: 10000,
    keySize: 64,
    plainTextSize: 24,
    saltSize: 64
  };

  this.docs = {
    blueprintFileName : 'blueprint.md',
    defaultLanguage: 'en-us',
    jadeTemplate: '/client/apidocs/templates/docs.jade',
    apiDocsLocalesFolder: '/client/apidocs/locales'
  };

  this.email = {
    enabled: true,
    from: 'SHAID@SmartDeviceLink.org',
    // SMTP settings for email sent from this server.
    smtp: {
      "host": "smtp.mandrillapp.com",
      "port": 587,
      "auth": {
        "user": '',
        "pass": ''
      }
    },
    templatesDirectory: path.resolve('../client/emailTemplates')
  };

  // Configure express settings
  this.express = {
    static : {
      maxAge: 0 // Set the max-age property for Cache-Control header (in ms). In production this needs to greater than zero toleverage browser caching
    }
  };

  // Configure i18n library
  this.i18n = {
    debug: false,                                 // Adds a bunch of debug text for i18next. Good to show if you are not sure why translations are failing.
    resGetPath: '../locales/__lng__/__ns__.json', // Point to the translation files.
    useCookie: false,                             // Do not use custom i18next cookie for language translation.
    fallbackLng: 'dev'
  };

  // Configure the reCAPTCHA to protect against bots.
  this.recaptcha = {
    clientKey: "0000000000000000000000000000000000000000",
    clientUrl: "https://www.google.com/recaptcha/api.js",
    enabled: true,
    serverKey: "1000000000000000000000000000000000000000",
    serverUrl: "https://www.google.com/recaptcha/api/siteverify"
  };

  // User role index values for quick reference when performing authentication.
  this.roles = {
    admin: 0,                   // Admin role index, should be the lowest value.
    oem: 1,                     // OEM role index, should allow access to SDL servers.
    developer: 2                // Developer role index, should allow access to Applications.
  };

  // Resolves to the path of the root directory.
  this.rootDirectory = path.resolve(path.dirname(require.main.filename), '..');

  // Settings for the Node server.
  this.server = {
    error: true,                // When true, error messages will be logged.
    debug: false,               // When true, debug messages will be logged.
    name: "SHAID",              // Name of the server
    port: 3000,                 // Port the server will be listening on.
    trace: false,                // When true, trace messages will be logged.
    requests: true,            // When true, requests messages will be logged.
    url: 'https://localhost:3000/'
  };

  // Configure express session options.
  this.session = {
    name: 'seedio.sid',          // Name of the server in the express session.
    secret: 'You will arrive at the gates of Valhalla, shiny and chrome!',
    resave: true,
    proxy: false,           // Should be true in production when secured behind NGINX and over HTTPS
    saveUninitialized: true,
    cookie: {
      maxAge: 604800000,    // 1 week (in ms)
      ttl:    7776000,      // 3 months (in seconds)
      secure: false         // Should be true in production when secured behind NGINX and over HTTPS
    }
  };

  this.authentication = {
    failedLoginAttempts: {
      deactivate: 10,
      recaptchaRequired: 5
    }
  };

  switch(process.env.NODE_ENV) {
    case "test":
      loadConfigFile(this, './test.js');
      break;

    case "dev":
    case "development":
      loadConfigFile(this, './development.js');
      break;

    case "pro":
    case "production":
      loadConfigFile(this, './production.js');
      break;

    default:
    case 'local':
      loadConfigFile(this, './local.js', true);
      break;
  }
};

var loadConfigFile = function(c, file, hideErrors) {
  try {
    (require(file))(c);
  } catch(err) {
    if(hideErrors) {
      console.log("Could not load the config file: " + file);
      console.log(err);
    }
  }
};


/* ************************************************** *
 * ******************** Public API
 * ************************************************** */

exports = module.exports = new Config();
exports = Config;