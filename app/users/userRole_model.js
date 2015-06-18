module.exports = function(app, config, log) {

  var crucial = require("crucial"),
      db = require('mongoose'),
      Schema = db.Schema,
      _ = require('lodash');

  var adminRole = config.roles.admin;


  /* ************************************************** *
   * ******************** Schema
   * ************************************************** */

  var UserRole = new Schema({
    name: { type: String },
    index: { type: Number, default: -1 }
  });


  /* ************************************************** *
   * ******************** Static Methods
   * ************************************************** */

  /**
   * A route method used to find a userRole by '_id'.  An
   * invalid ID will result in an error being returned to
   * the caller.  Otherwise the userRole found will be stored
   * in the req.userRole attribute.
   * @param req is the express request object.
   * @param res is the express response object.
   * @param cb is the next method to be called.
   * @param id is the userRole '_id' value to query for.
   */
  UserRole.statics.findByIdParam = function(req, res, cb, id) {
    if( ! db.Types.ObjectId.isValid(id)) {
      return res.setBadRequest('server.error.invalidObjectId');
    }

    db.model('UserRole').findById(id).exec(function(err, role) {
      if(err) {
        cb(err);
      } else if( ! role) {
        return res.setNotFound('server.error.notFound');
      } else {
        req.userRole = role;
        cb();
      }
    });
  };

  /**
   * Find the most permissive role from a list of roles.
   * @param roles is an array of userRole objects to be searched.
   * @returns {Object} the most permissive role object will be returned.
   */
  UserRole.statics.findMostPermissiveRole = function(roles) {
    if(roles === undefined || roles === null || roles.length === 0) {
      return undefined;
    }

    var role = { name: 'unknown', index: Number.MAX_VALUE };
    for(var i = 0; i < roles.length; i++) {
      if(roles[i].index > 0 && role.index > roles[i].index) {
        role = roles[i];
      }
    }

    return role;
  };

  /**
   * Check if the current user has permission to read the currently
   * queried User Role data.  If the user does not, a permission
   * denied message will be returned.  This assumes the currently
   * queried User Role is located in req.userRole.
   *
   * Admins can access all User Role data.
   * Users cannot access any User Role data.
   * OEMs cannot access any User Role data.
   */
  UserRole.statics.checkReadPermission = function(req, res, next) {
    if( ! _.isObject(req.user)) {
      return res.setUnauthorized();
    }

    var role = req.user.role;

    // Check for a valid user role value.
    if( ! role || role.index > adminRole) {
      return res.setPermissionDenied();
    }

    next();
  };

  /* ************************************************** *
   * ******************** Instance Methods
   * ************************************************** */

  /**
   * Checks if the current userRole instance has a higher
   * permission setting than the specified role parameter.
   * @param role is the role object to compare.
   * @returns {boolean} true if the userRole instance is more permissive than the role parameter.
   */
  UserRole.methods.isMorePermissive = function(role) {
    // If the parameter role is invalid, then the current
    // userRole instance is more permissive.
    if(role === undefined || role === null) {
      return true;
    }

    // Lower the index is equals the more permissive.
    return this.index <= role.index;
  };

  UserRole.methods.sanitize = function(user, cb) {
    return cb(undefined, this);
  };


  /* ************************************************** *
   * ******************** Event Methods
   * ************************************************** *
   * Methods that are executed when an event, such as
   * pre-save or pre-validate.                          */


  /* ************************************************** *
   * ******************** Mongoose Plugins
   * ************************************************** *
   * Enable additional functionality through 3rd party
   * plugins http://plugins.mongoosejs.com/             */

  db.plugin(crucial.mongoose);

  /* ************************************************** *
   * ******************** Exports
   * ************************************************** *
   * Export the model's methods and data so it can be
   * required by other parts of the application.        */

  db.model('UserRole', UserRole);

};