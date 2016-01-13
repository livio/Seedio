module.exports = function(app, config, log, dm) {

  function UserFixture() {
    dm.FixtureAdapter.call(this, 'User', dm, config, log);
  }

  UserFixture.prototype = dm.inherit(dm.FixtureAdapter.prototype);

  UserFixture.prototype.getNew = function() {
    var now = Date.now();
    return {
      "_id": "000000000000000000000099",
      "activated": true,
      "applications": [],
      "dateCreated": now,
      "deactivatedMessage": "",
      "deleted": false,
      "email": "newUser@localhost.com",
      "failedLoginAttempts": 0,
      "lastLogin": now,
      "lastUpdated": now,
      "lastUpdatedBy": "000000000000000000000000",
      "oauth2ClientId": "ed9d2323-339d-4724-8183-534416a4bd84",
      "password": "password",
      "passwordReset": "f23fasdffgt3h34h34g3r12f12",
      "requestedOemAccess": false,
      "roles": ["300000000000000000000000"],
      "securityQuestion": "What is your favorite color",
      "securityAnswer": "Blue. No, yel...",
      "sdlServers": [],
      "username": "newUser"
    };
  };

  UserFixture.prototype.getAll = function() {
    return [
      {
        "_id": "000000000000000000000000",
        "activated": true,
        "deactivatedMessage": "",
        "deleted": false,
        "email": "000000000000000000000000@localhost.com",
        "failedLoginAttempts": 0,
        "password": "password",
        "securityQuestion": "What is your favorite color?",
        "securityAnswer": "I'm Blind"
      },
      {
        "_id": "000000000000000000000001",
        "activated": false,
        "deactivatedMessage": "",
        "deleted": false,
        "email": "000000000000000000000001@localhost.com",
        "failedLoginAttempts": 0,
        "password": "password",
        "securityQuestion": "What is your favorite color",
        "securityAnswer": "I'm Blind"
      },
      {
        "_id": "000000000000000000000002",
        "activated": true,
        "deactivatedMessage": "",
        "deleted": true,
        "email": "000000000000000000000002@localhost.com",
        "failedLoginAttempts": 0,
        "password": "password",
        "securityQuestion": "What is your favorite color",
        "securityAnswer": "I'm Blind"
      },
    ];
  };

  return new UserFixture();
};