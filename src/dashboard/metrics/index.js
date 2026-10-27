'use strict';
const { MetricsEngine } = require('./MetricsEngine');
const retention         = require('../retention');
module.exports = new MetricsEngine(retention);
