/**
 * The configuration object stores default settings and methods
 * used to govern the application.
 */


/* ************************************************** *
 * ******************** Global Variables
 * ************************************************** */

var path = require('path');


/* ************************************************** *
 * ******************** Configuration Object
 * ************************************************** */

var Config = function() {

  // Information about the administrator of the server.
  this.admin = {
    email: ""                   // Email address used for notifications.
  };

  this.models = {
    user: {
      failedSecurityAttempts: {
        deactivate: 10,           // Number of failed attempts until the user account is deactivated.
        recaptchaRequired: 5      // Number of failed attempts until a ReCAPTCHA is required for security requests.
      },
      password: {
        changeRequiresCurrentPassword: false, // Whether or not the current user's password is required to set a new password.
        maxLength: 100,
        minLength: 4,
        resetTokenExpiration: 5
      },
      securityAnswer: {
        maxLength: 100,
        minLength: 1
      }
    }
  };

  // Crave is a module used to find and require files dynamically:  https://github.com/ssmereka/crave
  this.crave = {
    cache: {                    // Crave can store the list of files to load rather than create it each time.
      enable: false             // Disable caching of the list of files to load.  In production this should be enabled.
    },
    identification: {           // Variables related to how to find and require files are stored here.
      type: "filename",         // Determines how to find files.  Available options are: 'string', 'filename'
      identifier: "_"           // Determines how to identify the files.
    }
  };

  // Settings for the server's database connection.
  this.database = {
    initializeOnConnect: true,
    uri: "mongodb://localhost:27017/seedio_local"  // URI used to connect to the Mongo DB datastore.
  };

  this.docs = {
    blueprintFileName : 'blueprint.md',
    defaultLanguage: 'en-us',
    jadeTemplate: '/client/apidocs/templates/docs.jade',
    apiDocsLocalesFolder: '/client/apidocs/locales'
  };

  // Configure how emails are sent from the server.
  this.email = {
    enabled: true,              // Disable to stop all emails from actually being sent.
    from: 'me@domain.com',      // Default from email address for all email.
    smtp: {                     // SMTP settings for email sent from this server.
      "host": "smtp.mandrillapp.com",   // Host name of the SMTP server.  Mandrill by MailChimp is a great alternative to hosting your own.
      "port": 587,              // SMTP server's port.
      "auth": {                 // Authentication used by the SMTP server.
        "user": '',             // Username.
        "pass": ''              // Password.
      }
    },
    templatesDirectory: path.resolve('../client/emailTemplates')  // Directory where email templates are stored.
  };

  // Configure the Express framework:  http://expressjs.com/
  this.express = {
    static : {
      maxAge: 0 // Set the max-age property for Cache-Control header (in ms). In production this needs to greater than zero to leverage browser caching
    }
  };

  // Configure i18n library used for language translation:  http://i18next.com/
  this.i18n = {
    debug: false,                                 // Adds a bunch of debug text for i18next. Good to show if you are not sure why translations are failing.
    resGetPath: '../locales/__lng__/__ns__.json', // Point to the translation files.
    useCookie: false,                             // Do not use custom i18next cookie for language translation.
    fallbackLng: 'dev'
  };

  this.log = {
    error: true,
    debug: false,
    requests: false,
    trace: false
  };

  // Google's ReCAPTCHA  -- https://www.google.com/recaptcha/intro/index.html
  this.recaptcha = {
    clientKey: "0000000000000000000000000000000000000000",        // Client key assigned to you by the reCAPTCHA API.
    clientUrl: "https://www.google.com/recaptcha/api.js",         // Client reCAPTCHA endpoint.
    enabled: true,                                                // When false, disables checking of reCAPTCHA.
    serverKey: "1000000000000000000000000000000000000000",        // Server key assigned to you by the reCAPTCHA API.
    serverUrl: "https://www.google.com/recaptcha/api/siteverify"  // Server reCAPTCHA endpoint.
  };

  // Resolves to the path of the application's root directory.
  //this.rootDirectory = path.resolve(path.dirname(require.main.filename), '..');
  this.rootDirectory = path.resolve(__dirname, "../../");

  // Safeguard library settings https://goo.gl/kYg9Nv
  this.safeguard = {
    crypto: {                   // Balance security and server performance by tweaking the following settings.
      iterations: 10000,        // Choose iterations to satisfy the formula v-2^(n-1) > f-p  source:  http://goo.gl/tPVs1M
      keyLength: 64,            // Length of the text's hash value.
      plainTextLength: 24,      // When defined and an invalid string is hashed using the hasher, a random string of the specified size will be generated.
      saltLength: 64            // Size of the salt used when encrypting strings.
    }
  };

  // Settings for the Node server.
  this.server = {
    debug: false,               // Indicates the server is in debug mode and may perform unusual actions to assist the developer.
    domain: 'myDomainName.com', // Server's domain name.
    name: "SHAID",              // Name of the server
    port: 3000,                 // Port the server will be listening on.
    protocol: 'https'           // Default protocol used to communicate with the server.
  };

  // Configure express session options.
  this.session = {
    name: 'seedio.sid',         // Name of the server in the express session.
    secret: 'You will arrive at the gates of Valhalla, shiny and chrome!',
    resave: true,
    proxy: false,               // Should be true in production when secured behind NGINX and over HTTPS
    saveUninitialized: true,
    cookie: {
      maxAge: 604800000,    // 1 week (in ms)
      ttl:    7776000,      // 3 months (in seconds)
      secure: false         // Should be true in production when secured behind NGINX and over HTTPS
    }
  };

  this.models = {
    user: {
      usernameMaxLength: 600
    }
  };

  // Override configurations by loading the configuration file that
  // matches the name of the node environment specified.  If an
  // environment is not specified, Default to local.
  var file = (process.env.NODE_ENV) ? process.env.NODE_ENV : "local.js";
  try {
    (require(__dirname + "/" + file))(this);
  } catch(err) {
    console.log("Could not load the specified configuration file: %s/%s", __dirname, file);
    console.log(err);
  }

  // Set the server's URL parameter, based on the previously configured settings.
  this.server.url = (this.server.port == 80) ? this.server.protocol + "://" + this.server.domain : this.server.protocol + "://" + this.server.domain + ":" + this.server.port;

  this.log.debug = this.server.debug;

  this.libsDirectory = path.normalize(this.rootDirectory+'/server/libs/') ;

};


/* ************************************************** *
 * ******************** Public API
 * ************************************************** */

exports = module.exports = new Config();
exports = Config;