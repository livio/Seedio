var supertest = require('supertest');

exports.login = function (app, user, cb) {
  var agent = supertest.agent(app);

  var userId = (user && user._id) ? user._id : "000000000000000000000000";

  app.put('/api/1/users/' + userId + "?access_token=50d24972-50ae-4466-9911-49a8a1c78c7b").send({'password': 'password'}).end(function(err, res) {
    if(err) {
      cb(err);
    } else {
      var user = res.body.response;

      app.post('/api/1/login').send({ username: user.username, password: 'password'}).end(function (err, res) {
        if (err) {
          cb(err);
        }
        agent.saveCookies(res);
        cb(undefined, agent);
      });
    }
  });
};

exports.loginAndRequest = function(type, url, app, userId, cb) {
  var agent = supertest.agent(app);

  userId = (userId) ? userId : "000000000000000000000000";

  app.put('/api/1/users/' + userId + "?access_token=50d24972-50ae-4466-9911-49a8a1c78c7b").send({'password': 'password'}).end(function(err, res) {
    if(err) {
      cb(err);
    } else {
      var user = res.body.response;

      app.post('/api/1/login').send({ username: user.username, password: 'password'}).end(function (err, res) {
        if (err) {
          cb(err);
        }
        agent.saveCookies(res);
        var request = app[type.toLowerCase()](url);
        agent.attachCookies(request);
        cb(undefined, request, agent, user);
      });
    }
  });
}