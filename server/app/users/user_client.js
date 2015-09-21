/**
 * Defines routes related to user accounts.
 * @param app is the express application object.
 * @param config is the server's configuration object.
 * @param log is the server's current logger instance.
 */
module.exports = function(app, config, log) {

  var express = require('express');

  // Load models used by the controller.
  var User = db.model('User');


  /* ************************************************** *
   * ******************** User Client Routes
   * ************************************************** */

  // Create a router for the following group of requests.
  var client = express.Router();

  // Populate users by _id when present.
  client.param('id', User.routeFindById);

  // All the following user requests require authentication.
  //client.route('/*').all(policy.ensureLoggedInApi('/login'));

  // Use the web router and set the router's base url.
  app.use('/users', client);


  /* ************************************************** *
   * ******************** Web Route Methods
   * ************************************************** */





};