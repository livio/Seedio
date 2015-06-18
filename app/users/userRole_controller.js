module.exports = function(app, config, log, policy) {

  var db = require("mongoose"),
      express = require("express");

  var UserRole = db.model("UserRole");


  /* ************************************************** *
   * ******************** API Routes and Permissions
   * ************************************************** */

  var api = express.Router();

  // Populate User Roles by the '_id' attribute when present.
  api.param('id', UserRole.findByIdParam);

  // All User Role API requests require authentication.
  api.route('/*').all(policy.ensureLoggedInApi('/login'));

  // Query all User Roles.
  api.route('/')
    .get(UserRole.checkReadPermission, query);

  // Find a single User Role.
  api.route('/:id')
    .get(UserRole.checkReadPermission, find);

  app.use('/api/:version/userRoles', api);


  /* ************************************************** *
   * ******************** Route Methods
   * ************************************************** */

  function find(req, res, next) {
    res.setData(req.userRole, next);
  }

  function query(req, res, next) {
    UserRole.find({}).exec(function(err, roles) {
      if(err) {
        next(err);
      } else {
        res.setData(roles, next);
      }
    });
  }

};
