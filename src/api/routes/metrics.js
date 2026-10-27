'use strict';

const express      = require('express');
const router       = express.Router();
const metrics      = require('../../observability/metrics');
const requestDrain = require('../../runtime/requestDrain');

router.get('/', (_req, res) => {
  res.set('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
  res.set('Cache-Control', 'no-store');
  res.status(200).send(metrics.collect(requestDrain.activeCount()));
});

module.exports = router;
