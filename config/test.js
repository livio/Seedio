module.exports = function(c) {
  c.server.debug = false;
  c.server.trace = false;
  c.server.error = true;
  c.server.name = "SEED_TEST";
  c.server.port = 3001;
  c.server.databaseLog = false;

  c.database.initializeOnConnect = false;
  c.database.uri = "mongodb://localhost:27017/seedio_test";

  // Turn off actually sending emails for tests.
  c.email.enabled = false;

  // Configure the reCAPTCHA to protect against bots.
  c.recaptcha = {
    enabled: false
  };
};