module.exports = function(app, config, log, data, dm) {

  var assert = require('assert'),
      async = require('async'),
      i18n = require('i18next'),
      should = require('should'),
      _ = require('lodash');

  var adminAccessToken = "",
    oemAccessToken = "",
    developerAccessToken = "";


  /* ************************************************** *
   * ******************** Private Methods
   * ************************************************** */

  var validateUserRoles = function(userRoles, cb) {
    if(userRoles == undefined || userRoles == null) {
      cb(new Error("Invalid userRoles value of " + userRoles));
    }

    var tasks = [];

    for(var i = 0; i < userRoles.length; i++) {
      tasks.push(createValidateUserRoleMethod(userRoles[i]));
    }

    async.parallel(tasks, function(err, results) {
      cb(err);
    });
  };

  var createValidateUserRoleMethod = function(userRole, currentUserRole) {
    return function(cb) {
      validateUserRole(userRole, cb);
    }
  };

  var validateUserRole = function(userRole, cb) {
    assert.notEqual(userRole, undefined);
    assert.notEqual(userRole, null);

    cb();
  };

  var compareUserRoleToResponse = function(response, userRole) {
    if(userRole._id) {
      response._id.should.equal(userRole._id.toLowerCase());
    }

    // Required to be in response
    assert.notEqual(response.name, undefined);
    assert.notEqual(response.index, undefined);

    assert.equal(response.name, userRole.name);
    assert.equal(response.index, userRole.index);
  };


  /* ************************************************** *
   * ******************** Test Suites
   * ************************************************** */

  describe('User Roles', function() {

    /* ************************************************** *
     * ******************** Lifecycle Methods
     * ************************************************** */

    before(function(done) {
      dm.getAccessToken(data, config.roles.admin, function(err, token) {
        if(err) {
          done(err);
        }
        adminAccessToken = token;

        dm.getAccessToken(data, config.roles.oem, function(err, token) {
          if(err) {
            done(err);
          }
          oemAccessToken = token;

          dm.getAccessToken(data, config.roles.user, function(err, token) {
            if(err) {
              done(err);
            }
            developerAccessToken = token;

            done();
          });
        });
      });
    });

    beforeEach(function(done) {
      dm.addData(data, done);
    });

    afterEach(function(done) {
      dm.removeData(data, done);
    });


    /* ************************************************** *
     * ******************** Query All
     * ************************************************** */

    describe('can all be queried', function() {

      it('by an admin', function(done) {
        app.get('/api/1/userroles?access_token=' + adminAccessToken).expect('Content-Type', /json/).expect(200).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            dm.validateResponseObject(responseObj);

            // Make sure all the SDL servers were returned for an admin.
            assert.equal(responseObj.response.length, data.UserRole.getAll().length);

            validateUserRoles(responseObj.response, function(err) {
              done(err);
            });
          }
        });
      });

    });

    describe('cannot all be queried', function() {

      it('by an OEM', function(done) {
        var oemUserId = "000000000000000000000001";

        dm.getUserAccessToken(data, oemUserId, function(err, accessToken) {
          app.get('/api/1/userroles?access_token=' + accessToken.token).expect('Content-Type', /json/).expect(403).end(function(err, res) {
            if(err) {
              done(err);
            } else {
              dm.validateForbiddenObject(res.body);
              done();
            }
          });
        });
      });

      it('by a Developer', function(done) {
        var developerUserId = "000000000000000000000002";

        dm.getUserAccessToken(data, developerUserId, function(err, accessToken) {
          app.get('/api/1/userroles?access_token=' + accessToken.token).expect('Content-Type', /json/).expect(403).end(function(err, res) {
            if(err) {
              done(err);
            } else {
              dm.validateForbiddenObject(res.body);
              done();
            }
          });
        });
      });

      it('by an anonymous user', function(done) {
        app.get('/api/1/userroles?access_token=invalidAccessToken').expect('Content-Type', /json/).expect(401).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            // Make sure an unauthorized error is returned.
            dm.validateUnauthorized(res.body);
            done();
          }
        });
      });

    });


    /* ************************************************** *
     * ******************** Query One
     * ************************************************** */

    describe('can be individually queried', function() {

      it('by an admin', function(done) {
        var userRole = data.UserRole.getAll()[0];

        app.get('/api/1/userroles/' + userRole._id + '?access_token=' + adminAccessToken).expect('Content-Type', /json/).expect(200).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            dm.validateResponseObject(responseObj);

            // Ensure the queried SDL server is exactly what we expect.
            compareUserRoleToResponse(responseObj.response, userRole);

            validateUserRole(responseObj.response, function(err) {
              done(err);
            });
          }
        });
      });

    });

    describe('cannot be individually queried', function() {

      it('by an OEM', function(done) {
        var oemUserId = "000000000000000000000001",
          userRole = data.UserRole.getAll()[0];

        dm.getUserAccessToken(data, oemUserId, function(err, accessToken) {
          if(err) {
            done(err);
          } else {
            app.get('/api/1/userroles/' + userRole._id + '?access_token=' + accessToken.token).expect('Content-Type', /json/).expect(403).end(function(err, res) {
              if(err) {
                done(err);
              } else {
                dm.validateForbiddenObject(res.body);
                done();
              }
            });
          }
        });
      });

      it('by a Developer', function(done) {
        var developerUserId = "000000000000000000000002",
          userRole = data.UserRole.getAll()[0];

        dm.getUserAccessToken(data, developerUserId, function(err, accessToken) {
          if(err) {
            done(err);
          } else {
            app.get('/api/1/userroles/' + userRole._id + '?access_token=' + accessToken.token).expect('Content-Type', /json/).expect(403).end(function(err, res) {
              if(err) {
                done(err);
              } else {
                dm.validateForbiddenObject(res.body);
                done();
              }
            });
          }
        });
      });

      it('by an anonymous user', function(done) {
        var userRole = data.UserRole.getAll()[0];
        app.get('/api/1/userroles/' + userRole._id + '?access_token=InvalidAccessToken').expect('Content-Type', /json/).expect(401).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            dm.validateUnauthorized(res.body);
            done();
          }
        });
      });

      it('with an invalid objectId', function(done) {
        app.get('/api/1/userroles/0000?access_token=' + adminAccessToken).expect('Content-Type', /json/).expect(400).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            dm.validateBadRequestObject(res.body, 'server.error.invalidObjectId');
            done();
          }
        });
      });

    });

  });

};