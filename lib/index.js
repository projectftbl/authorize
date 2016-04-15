var _ = require('lodash');

var Authorizer = function(claims) {
  if (this instanceof Authorizer === false) return new Authorizer(claims);

  this.claims = init(claims);
};

Authorizer.rights = {
  Nothing : 0
, Create  : 1
, Read    : 2
, Update  : 4
, Destroy : 8
, Lookup  : 16
};

var r = Authorizer.rights;

Authorizer.permissions = {
  None        : r.Nothing
, Lookup      : r.Lookup
, ReadOnly    : r.Lookup | r.Read
, Editor      : r.Lookup | r.Read | r.Update
, FullAccess  : r.Lookup | r.Read | r.Update | r.Create | r.Destroy
};

var p = Authorizer.permissions;

var init = function(claims) {
  if (claims == null) return;

  if (_(claims).isArray() === false) claims = [ claims ];

  var fromArray = function(claim) {
    return _(claim).isArray()
      ? { entity: claim[0], right: claim[1] }
      : claim;
  };

  claims = claims.map(fromArray);

  return _
  .chain(claims)
  .pluck('entity')
  .uniq()
  .map(function(entity) {
    return { entity: entity, right: combine(claims, entity) };
  })
  .value();
};

Authorizer.fromUser = function(user) {
  var roles = (user.roles || []).concat({ claims: user.claims });

  return _.chain(roles)

  .map(function(role) {
    return _(role.claims).map(function(claim) {
      return [ claim.entity, claim.right ];
    }).value();
  })

  .flatten(true)
  .value();
};

var combine = function(claims, entity) {
  return _
  .chain(claims)
  .filter(function(c) { return c.entity === entity; })
  .pluck('right')
  .reduce(function(l, r) { return l | r }, 0)
  .value();
};

Authorizer.prototype.can = function(entity, right) {
  if (right == null) { // claim as string, e.g. 'read thing'
    var parts = entity.split(' ');

    if (parts.length < 2) return false;

    var entity = parts[1]
      , right  = r[parts[0].charAt(0).toUpperCase() + parts[0].substr(1)];
  }

  if (right == null) return false;

  var claim = _(this.claims).find(function(c) { return c.entity === entity; });

  if (claim == null) return false;

  if (claim.right === p.None && right !== r.Nothing) return false;
  if (claim.right === p.None && right === r.Nothing) return true;

  return (claim.right | right) === claim.right;
};

module.exports = Authorizer;