const express = require('express');
const debug = require('debug')('sc2:server');
const { authenticate, verifyPermissions } = require('../helpers/middleware');
const { encode } = require('steem/lib/auth/memo');
const { issueUserToken } = require('../helpers/token');
const router = express.Router();

/** Get my account details */
router.all('/me', authenticate(), async (req, res, next) => {
  const accounts = await req.steem.api.getAccountsAsync([req.user]);
  res.json(accounts[0]);
});

/** Get applications */
router.all('/apps', async (req, res, next) => {
  const query = 'SELECT client_id FROM apps';
  const apps = await req.db.query(query);
  res.json(apps);
});

/** Get my applications */
router.all('/apps/me', authenticate('user'), async (req, res, next) => {
  const query = 'SELECT * FROM apps WHERE ${admin} = ANY(admins)';
  const apps = await req.db.query(query, { admin: req.user });
  res.json(apps);
});

/** Get application details */
router.get('/apps/@:clientId', async (req, res, next) => {
  const { clientId } = req.params;
  const query = 'SELECT * FROM apps WHERE client_id = ${client_id} LIMIT 1';
  const apps = await req.db.query(query, { client_id: clientId });
  if (!apps[0]) return next();
  if (!req.user || !apps[0].admins.includes(req.user)) {
    delete apps[0].secret;
  }
  res.json(apps[0]);
});

/** Update application */
router.put('/apps/@:clientId', authenticate('user'), async (req, res, next) => {
  const { clientId } = req.params;
  const app = req.body;
  console.log(app);
  const query = 'UPDATE apps SET ' +
    'name = ${name}, ' +
    'description = ${description}, ' +
    'icon = ${icon}, ' +
    'redirect_uris = ${redirect_uris} ' +
    'WHERE client_id = ${client_id} AND ${admin} = ANY(admins)';
  try {
    await req.db.query(query, {
      name: app.name,
      description: app.description,
      icon: app.icon,
      redirect_uris: app.redirect_uris,
      client_id: clientId,
      admin: req.user,
    });
  } catch (err) {
    return next(err);
  }
  res.json({ success: true });
});

/** Broadcast transactions */
router.post('/broadcast', authenticate('app'), verifyPermissions, async (req, res, next) => {
  const allowedOperations = ['comment', 'comment_options', 'vote', 'custom_json']; // custom_json
  const { operations } = req.body;
  let isAuthorized = true;

  operations.forEach((operation) => {
    /** Check if operation is allowed */
    if (allowedOperations.indexOf(operation[0]) === -1) {
      isAuthorized = false;
    }
    /** Check if author of the operation is user */
    if (
      operation[1].voter !== req.user &&
      operation[1].author !== req.user &&
      (operation[1].required_posting_auths.length && operation[1].required_posting_auths[0] !== req.user)
    ) {
      isAuthorized = false;
    }
  });

  if (!isAuthorized) {
    res.status(401).send('Unauthorized!');
  } else {
    debug(`Broadcast transaction for @${req.user} from app @${req.proxy}`);
    req.steem.broadcast.send(
      { operations, extensions: [] },
      { posting: process.env.BROADCASTER_POSTING_WIF },
      (err, result) => {
        console.log(err, result);
        res.json({ errors: err, result });
      }
    );
  }
});

router.all('/login/challenge', async (req, res, next) => {
  const username = req.query.username;
  const role = req.query.role || 'posting';
  const token = issueUserToken(username);
  const accounts = await req.steem.api.getAccountsAsync([username]);
  const publicWif = accounts[0][role].key_auths[0][0];
  const code = encode(process.env.BROADCASTER_POSTING_WIF, publicWif, `#${token}`);
  res.json({
    username,
    code,
  });
});

module.exports = router;