/**
 * Local Environment Configuration
 * Default settings and methods used to govern the application
 * while running on the developer's local machine.
 */


/* ************************************************** *
 * ******************** Configuration Object
 * ************************************************** */

module.exports = function(c) {

  // Connection URI for the database.
  c.database.uri = "mongodb://localhost:27017/seedio_local";

  // SMTP server's username and password.
  c.email.smtp.auth.user = '';
  c.email.smtp.auth.pass = '';

  // Enable/Disable i18n library's debug setting.
  c.i18n.debug = false;

  // Enable/Disable log levels.
  c.log.error = true;
  c.log.debug = true;
  c.log.trace = false;
  c.log.requests = false;

  // Credentials for Google's reCAPTCHA, used to protect against bots.
  c.recaptcha.clientKey = "";
  c.recaptcha.serverUrl = "";

  // Enable/Disable debug mode for the server.
  c.server.debug = true;

  // Set the server's URI parameters.
  c.server.domain = "localhost";
  c.server.protocol = "http";
  c.server.port = 3000;

  // Set the secret used to secure the session.
  c.session.secret = 'You will arrive at the gates of Valhalla, shiny and chrome!';

};