/**
 * Test Environment Configuration
 * Default settings and methods used to govern the application
 * while running automated tests.
 */


/* ************************************************** *
 * ******************** Configuration Object
 * ************************************************** */

module.exports = function(c) {

  // Connection URI and settings for the database.
  c.database.initializeOnConnect = false;
  c.database.uri = "mongodb://localhost:27017/seedio_test";

  // Disable emails when testing.
  c.email.enabled = false;

  // Enable/Disable i18n library's debug setting.
  c.i18n.debug = false;

  // Enable/Disable log levels.
  c.log.error = true;
  c.log.debug = false;
  c.log.trace = false;
  c.log.requests = false;

  // Disable Google's reCAPTCHA so we can automate tests.
  c.recaptcha.enabled = false;

  // Enable/Disable debug mode for the server.
  c.server.debug = false;

  // Set the server's settings
  c.server.domain = "localhost";
  c.server.name = "SEED_TEST";
  c.server.protocol = "http";
  c.server.port = 3001;

  // Set the secret used to secure the session.
  c.session.secret = 'Little bits...';

};




