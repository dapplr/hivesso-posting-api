const client = require('./client');
const config = require('../config.json');
const jwt = require('jsonwebtoken');
const lodash = require('lodash');

/**
 * Check if user allow app proxy account to post on his behalf
 * And if app allow @hivesigner to post on his behalf
 */
export const verifyPermissions = async (req, res, next) => {
  let accounts;
  try {
    accounts = await client.database.getAccounts([req.proxy, req.user]);
  } catch (e) {
    console.error('Unable to load accounts from hived', req.proxy, req.user, e);
  }

  if (!lodash.has(accounts, '[0].name') || !lodash.has(accounts, '[1].name')) {
    res.status(401).json({
      error: 'unauthorized_client',
      error_description: `The app @${req.proxy} or user @${req.user} account failed to load`,
    });
  } else {
    const userAccountAuths = accounts[1].posting.account_auths.map((account) => account[0]);
    if (userAccountAuths.indexOf(process.env.BROADCASTER_USERNAME) === -1) {
      res.status(401).json({
        error: 'unauthorized_client',
        error_description: `Broadcaster account doesn't have permission to broadcast for @${req.user}`,
      });
    } else {
      next();
    }
  }
};

export const strategy = (req, res, next) => {
  let authorization = req.get('authorization');
  if (authorization) authorization = authorization.replace(/^(Bearer|Basic)\s/, '').trim();
  const token = authorization
    || req.query.access_token
    || req.body.access_token
    || req.query.code
    || req.body.code
    || req.query.refresh_token
    || req.body.refresh_token;

  if (token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
      const userData = JSON.parse(decoded.data)

      /* eslint-disable no-param-reassign */
      req.token = token;
      req.role = 'app';
      req.user = userData.username;
      req.proxy = userData.app || 'dapplr';
      req.scope = config.authorized_operations;
      req.type = 'signature';
      /* eslint-enable no-param-reassign */

      next();
    } catch (e) {
      console.log(new Date().toISOString(), 'Access Token decoding failed', e);
      next();
    }
  } else {
    next();
  }
};

export const authenticate = (roles) => async (req, res, next) => {
  const role = Array.isArray(roles) && req.role && roles.includes(req.role)
    ? req.role : roles;

  if (!req.role || (role && req.role !== role)) {
    res.status(401).json({
      error: 'invalid_grant',
      error_description: 'The token has invalid role',
    });
  } else {
    next();
  }
};
