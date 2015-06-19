module.exports = function(app, config, log, dm) {
  var UserRoleData = function() {
    this.name = "UserRole"
  };

  var insertAll = function(cb) {
    dm.addItems('UserRole', getAll(), cb);
  };

  var deleteAll = function(cb) {
    dm.removeItems('UserRole', getAll(), cb);
  };

  var getAll = function() {
    return [
      {
        "_id": "300000000000000000000000",
        "index": config.roles.admin,
        "name": "Admin"
      },
      {
        "_id": "300000000000000000000001",
        "index": config.roles.oem,
        "name": "OEM"
      },
      {
        "_id": "300000000000000000000002",
        "index": config.roles.developer,
        "name": "Developer"
      }
    ];
  };

  UserRoleData.prototype.insertAll = insertAll;
  UserRoleData.prototype.deleteAll = deleteAll;
  UserRoleData.prototype.getAll = getAll;

  return new UserRoleData();
};