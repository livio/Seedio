module.exports = function(c) {
  c.admin.email = 'corey@livio.io';

  c.email.enabled = true;
  c.email.smtp.auth.user = 'it@livioconnect.com';
  c.email.smtp.auth.pass = 'ktXS3QgBhN14byz7H9cV0A';

  c.server.debug = true;
  //c.database.uri = "mongodb://hal:9000@ds029317.mongolab.com:29317/shaid_dev_large_data_set";
  c.server.port = 3000;
  c.server.trace = true;
  c.server.url = 'http://127.0.0.1:3000';

  c.server.debug = true;
  c.database.uri = "mongodb://localhost:27017/seedio_local";
  c.server.port = 3000;
  c.server.trace = true;
  c.server.url = 'http://127.0.0.1:3000';

  // Configure the reCAPTCHA to protect against bots.
  c.recaptcha = {
    clientKey: "6LcT6gMTAAAAAFmsUlquDcVxY38DMKPplZCYubG2",
    clientUrl: "https://www.google.com/recaptcha/api.js",
    enabled: true,
    serverKey: "6LcT6gMTAAAAAL6LDXw3bGE7QKkBnrxNPwN77ued",
    serverUrl: "https://www.google.com/recaptcha/api/siteverify"
  };
};