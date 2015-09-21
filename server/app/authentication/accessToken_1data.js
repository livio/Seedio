module.exports = function(app, config, log, dm) {
  var AccessTokenData = function() {
    this.name = "AccessToken";
  };

  var insertAll = function(cb) {
    dm.addItems('AccessToken', getAll(), cb);
  };

  var deleteAll = function(cb) {
    dm.removeItems('AccessToken', getAll(), cb);
  };

  var getAll = function() {
    return [
      { // Admin Access Token
        "_id": "400000000000000000000000",
        "token": "50d24972-50ae-4466-9911-49a8a1c78c7b",
        "client": "200000000000000000000000",
        "user": "000000000000000000000000"
      },
      { // OEM Access Token
        "_id": "400000000000000000000001",
        "token": "a448257c-c771-4a20-8d0b-15465ecbb5d0",
        "client": "200000000000000000000000",
        "user": "000000000000000000000001"
      },
      { // Developer Access Token
        "_id": "400000000000000000000002",
        "token": "4a18698a-713e-4933-a65e-85471ecd82dc",
        "client": "200000000000000000000000",
        "user": "000000000000000000000002"
      },
      { // OEM Access Token
        "_id": "400000000000000000000003",
        "token": "a448257c-c771-4a20-8d0b-15465ecbb5d1",
        "client": "200000000000000000000000",
        "user": "000000000000000000000003"
      },
      { // Developer 2 Access Token
        "_id": "400000000000000000000004",
        "token": "4a18698a-713e-4933-a65e-85471ecd82dd",
        "client": "200000000000000000000000",
        "user": "000000000000000000000005"
      },
      { // OEM Access Token
        "_id": "400000000000000000000005",
        "token": "4a18698a-713e-4933-a65e-85471ecd82de",
        "client": "200000000000000000000000",
        "user": "000000000000000000000006"
      },
      { // New user access token.
        "_id": "400000000000000000000006",
        "token": "4a18698a-713e-4933-a65e-85471ecd82df",
        "client": "200000000000000000000000",
        "user": "000000000000000000000099"
      }
    ];
  };

  AccessTokenData.prototype.insertAll = insertAll;
  AccessTokenData.prototype.deleteAll = deleteAll;
  AccessTokenData.prototype.getAll = getAll;

  return new AccessTokenData();
};