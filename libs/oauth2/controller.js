module.exports = function(app, config, log, oauth2) {

  var db = require("mongoose"),
    express = require("express"),
    router = express.Router(),
    oauth2orize = require("oauth2orize"),
    passport = require('passport'),
    login = require('connect-ensure-login');

  router.route('/authorize')
    .get(oauth2.authorization)
    .post(oauth2.decision);

  router.route('/token')
    .get(oauth2.token)
    .post(oauth2.token);

  app.use('/api/:version/oauth2', router);

  var r = express.Router();
  r.route('/').get(function(req, res, next) {
    console.log(req.params);
    console.log(req.body);
    console.log(req.url);
    console.log(req.query);
    next();
  });

  app.use('/api/1/test', r);

};
