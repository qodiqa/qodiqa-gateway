'use strict';

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const { emit }            = require('../../../../services/logger');
const { loadLogShipConfig } = require('../config');

describe('loadLogShipConfig — ELK', () => {
  let savedEnv;

  beforeEach(() => {
    savedEnv = { ...process.env };
    delete process.env.QODIQA_LOGSHIP_ELK_ENABLED;
    delete process.env.QODIQA_LOGSHIP_ELK_URL;
    jest.clearAllMocks();
  });

  afterEach(() => {
    Object.keys(process.env).forEach(k => { if (!(k in savedEnv)) delete process.env[k]; });
    Object.assign(process.env, savedEnv);
  });

  it('ELK disabled by default', () => {
    const cfg = loadLogShipConfig();
    expect(cfg.elk.enabled).toBe(false);
  });

  it('ELK enabled + valid URL → enabled=true, valid=true', () => {
    process.env.QODIQA_LOGSHIP_ELK_ENABLED = 'true';
    process.env.QODIQA_LOGSHIP_ELK_URL     = 'https://logstash.company.com';
    const cfg = loadLogShipConfig();
    expect(cfg.elk.enabled).toBe(true);
    expect(cfg.elk.valid).toBe(true);
    expect(cfg.elk.url).toBe('https://logstash.company.com');
  });

  it('ELK enabled + missing URL → valid=false + ERROR emitted', () => {
    process.env.QODIQA_LOGSHIP_ELK_ENABLED = 'true';
    const cfg = loadLogShipConfig();
    expect(cfg.elk.valid).toBe(false);
    expect(emit).toHaveBeenCalledWith('ERROR', 'LOGSHIP_CONFIG_INVALID',
      expect.objectContaining({ destination: 'elk' }),
    );
  });

  it('ELK enabled + HTTP (not HTTPS) URL → valid=false + ERROR emitted', () => {
    process.env.QODIQA_LOGSHIP_ELK_ENABLED = 'true';
    process.env.QODIQA_LOGSHIP_ELK_URL     = 'http://logstash.company.com';
    const cfg = loadLogShipConfig();
    expect(cfg.elk.valid).toBe(false);
    expect(emit).toHaveBeenCalledWith('ERROR', 'LOGSHIP_CONFIG_INVALID',
      expect.objectContaining({ destination: 'elk' }),
    );
  });

  // #6
  it('ELK schema defaults to "raw" when unset', () => {
    process.env.QODIQA_LOGSHIP_ELK_ENABLED = 'true';
    process.env.QODIQA_LOGSHIP_ELK_URL     = 'https://logstash.company.com';
    const cfg = loadLogShipConfig();
    expect(cfg.elk.schema).toBe('raw');
  });

  it('ELK schema="ecs" is accepted', () => {
    process.env.QODIQA_LOGSHIP_ELK_ENABLED = 'true';
    process.env.QODIQA_LOGSHIP_ELK_URL     = 'https://logstash.company.com';
    process.env.QODIQA_LOGSHIP_ELK_SCHEMA  = 'ecs';
    const cfg = loadLogShipConfig();
    expect(cfg.elk.schema).toBe('ecs');
  });

  it('an unrecognized ELK schema falls back to "raw" and emits an ERROR rather than hard-failing startup', () => {
    process.env.QODIQA_LOGSHIP_ELK_ENABLED = 'true';
    process.env.QODIQA_LOGSHIP_ELK_URL     = 'https://logstash.company.com';
    process.env.QODIQA_LOGSHIP_ELK_SCHEMA  = 'not-a-real-schema';
    const cfg = loadLogShipConfig();
    expect(cfg.elk.schema).toBe('raw');
    expect(emit).toHaveBeenCalledWith('ERROR', 'LOGSHIP_CONFIG_INVALID',
      expect.objectContaining({ destination: 'elk' }),
    );
  });
});

describe('loadLogShipConfig — Datadog', () => {
  let savedEnv;

  beforeEach(() => {
    savedEnv = { ...process.env };
    delete process.env.QODIQA_LOGSHIP_DATADOG_ENABLED;
    delete process.env.QODIQA_LOGSHIP_DATADOG_API_KEY;
    delete process.env.QODIQA_LOGSHIP_DATADOG_SITE;
    jest.clearAllMocks();
  });

  afterEach(() => {
    Object.keys(process.env).forEach(k => { if (!(k in savedEnv)) delete process.env[k]; });
    Object.assign(process.env, savedEnv);
  });

  it('Datadog disabled by default', () => {
    const cfg = loadLogShipConfig();
    expect(cfg.datadog.enabled).toBe(false);
  });

  it('Datadog enabled + API key → valid=true', () => {
    process.env.QODIQA_LOGSHIP_DATADOG_ENABLED  = 'true';
    process.env.QODIQA_LOGSHIP_DATADOG_API_KEY  = 'dd-api-key-123';
    const cfg = loadLogShipConfig();
    expect(cfg.datadog.enabled).toBe(true);
    expect(cfg.datadog.valid).toBe(true);
    expect(cfg.datadog.apiKey).toBe('dd-api-key-123');
  });

  it('Datadog site defaults to datadoghq.com', () => {
    process.env.QODIQA_LOGSHIP_DATADOG_ENABLED = 'true';
    process.env.QODIQA_LOGSHIP_DATADOG_API_KEY = 'dd-api-key-123';
    const cfg = loadLogShipConfig();
    expect(cfg.datadog.site).toBe('datadoghq.com');
  });

  it('Datadog enabled + missing API key → valid=false + ERROR emitted', () => {
    process.env.QODIQA_LOGSHIP_DATADOG_ENABLED = 'true';
    const cfg = loadLogShipConfig();
    expect(cfg.datadog.valid).toBe(false);
    expect(emit).toHaveBeenCalledWith('ERROR', 'LOGSHIP_CONFIG_INVALID',
      expect.objectContaining({ destination: 'datadog' }),
    );
  });
});

describe('loadLogShipConfig — Splunk', () => {
  let savedEnv;

  beforeEach(() => {
    savedEnv = { ...process.env };
    delete process.env.QODIQA_LOGSHIP_SPLUNK_ENABLED;
    delete process.env.QODIQA_LOGSHIP_SPLUNK_URL;
    delete process.env.QODIQA_LOGSHIP_SPLUNK_TOKEN;
    jest.clearAllMocks();
  });

  afterEach(() => {
    Object.keys(process.env).forEach(k => { if (!(k in savedEnv)) delete process.env[k]; });
    Object.assign(process.env, savedEnv);
  });

  it('Splunk disabled by default', () => {
    expect(loadLogShipConfig().splunk.enabled).toBe(false);
  });

  it('Splunk enabled + URL + token → valid=true', () => {
    process.env.QODIQA_LOGSHIP_SPLUNK_ENABLED = 'true';
    process.env.QODIQA_LOGSHIP_SPLUNK_URL     = 'https://splunk.company.com:8088';
    process.env.QODIQA_LOGSHIP_SPLUNK_TOKEN   = 'splunk-hec-token';
    const cfg = loadLogShipConfig();
    expect(cfg.splunk.valid).toBe(true);
    expect(cfg.splunk.url).toBe('https://splunk.company.com:8088');
    expect(cfg.splunk.token).toBe('splunk-hec-token');
  });

  it('Splunk enabled + missing token → valid=false + ERROR emitted', () => {
    process.env.QODIQA_LOGSHIP_SPLUNK_ENABLED = 'true';
    process.env.QODIQA_LOGSHIP_SPLUNK_URL     = 'https://splunk.company.com:8088';
    const cfg = loadLogShipConfig();
    expect(cfg.splunk.valid).toBe(false);
    expect(emit).toHaveBeenCalledWith('ERROR', 'LOGSHIP_CONFIG_INVALID',
      expect.objectContaining({ destination: 'splunk' }),
    );
  });

  it('Splunk enabled + missing URL → valid=false + ERROR emitted', () => {
    process.env.QODIQA_LOGSHIP_SPLUNK_ENABLED = 'true';
    process.env.QODIQA_LOGSHIP_SPLUNK_TOKEN   = 'tok';
    const cfg = loadLogShipConfig();
    expect(cfg.splunk.valid).toBe(false);
    expect(emit).toHaveBeenCalledWith('ERROR', 'LOGSHIP_CONFIG_INVALID',
      expect.objectContaining({ destination: 'splunk' }),
    );
  });

  // #6
  it('Splunk schema defaults to "raw" when unset', () => {
    process.env.QODIQA_LOGSHIP_SPLUNK_ENABLED = 'true';
    process.env.QODIQA_LOGSHIP_SPLUNK_URL     = 'https://splunk.company.com:8088';
    process.env.QODIQA_LOGSHIP_SPLUNK_TOKEN   = 'tok';
    const cfg = loadLogShipConfig();
    expect(cfg.splunk.schema).toBe('raw');
  });

  it('Splunk schema="cim" is accepted', () => {
    process.env.QODIQA_LOGSHIP_SPLUNK_ENABLED = 'true';
    process.env.QODIQA_LOGSHIP_SPLUNK_URL     = 'https://splunk.company.com:8088';
    process.env.QODIQA_LOGSHIP_SPLUNK_TOKEN   = 'tok';
    process.env.QODIQA_LOGSHIP_SPLUNK_SCHEMA  = 'cim';
    const cfg = loadLogShipConfig();
    expect(cfg.splunk.schema).toBe('cim');
  });

  it('an unrecognized Splunk schema falls back to "raw" and emits an ERROR rather than hard-failing startup', () => {
    process.env.QODIQA_LOGSHIP_SPLUNK_ENABLED = 'true';
    process.env.QODIQA_LOGSHIP_SPLUNK_URL     = 'https://splunk.company.com:8088';
    process.env.QODIQA_LOGSHIP_SPLUNK_TOKEN   = 'tok';
    process.env.QODIQA_LOGSHIP_SPLUNK_SCHEMA  = 'bogus';
    const cfg = loadLogShipConfig();
    expect(cfg.splunk.schema).toBe('raw');
    expect(emit).toHaveBeenCalledWith('ERROR', 'LOGSHIP_CONFIG_INVALID',
      expect.objectContaining({ destination: 'splunk' }),
    );
  });
});

describe('loadLogShipConfig — SIEM', () => {
  let savedEnv;

  beforeEach(() => {
    savedEnv = { ...process.env };
    delete process.env.QODIQA_LOGSHIP_SIEM_ENABLED;
    delete process.env.QODIQA_LOGSHIP_SIEM_MODE;
    delete process.env.QODIQA_LOGSHIP_SIEM_URL;
    delete process.env.QODIQA_LOGSHIP_SIEM_TOKEN;
    delete process.env.QODIQA_LOGSHIP_SIEM_SYSLOG_HOST;
    delete process.env.QODIQA_LOGSHIP_SIEM_SYSLOG_PORT;
    delete process.env.QODIQA_LOGSHIP_SIEM_SYSLOG_PROTO;
    delete process.env.ALERT_SIEM_URL;
    delete process.env.ALERT_SIEM_SYSLOG_HOST;
    delete process.env.ALERT_SIEM_MODE;
    jest.clearAllMocks();
  });

  afterEach(() => {
    Object.keys(process.env).forEach(k => { if (!(k in savedEnv)) delete process.env[k]; });
    Object.assign(process.env, savedEnv);
  });

  it('SIEM disabled by default', () => {
    expect(loadLogShipConfig().siem.enabled).toBe(false);
  });

  it('SIEM enabled + http mode + valid HTTPS URL → valid=true', () => {
    process.env.QODIQA_LOGSHIP_SIEM_ENABLED = 'true';
    process.env.QODIQA_LOGSHIP_SIEM_URL     = 'https://siem.company.com/hec';
    const cfg = loadLogShipConfig();
    expect(cfg.siem.enabled).toBe(true);
    expect(cfg.siem.mode).toBe('http');
    expect(cfg.siem.valid).toBe(true);
  });

  it('SIEM enabled + http mode + missing URL → valid=false + ERROR emitted', () => {
    process.env.QODIQA_LOGSHIP_SIEM_ENABLED = 'true';
    const cfg = loadLogShipConfig();
    expect(cfg.siem.valid).toBe(false);
    expect(emit).toHaveBeenCalledWith('ERROR', 'LOGSHIP_CONFIG_INVALID',
      expect.objectContaining({ destination: 'siem' }),
    );
  });

  it('SIEM enabled + syslog mode + host present → valid=true', () => {
    process.env.QODIQA_LOGSHIP_SIEM_ENABLED = 'true';
    process.env.QODIQA_LOGSHIP_SIEM_MODE    = 'syslog';
    process.env.QODIQA_LOGSHIP_SIEM_SYSLOG_HOST = 'collector.internal';
    const cfg = loadLogShipConfig();
    expect(cfg.siem.valid).toBe(true);
    expect(cfg.siem.syslogHost).toBe('collector.internal');
    expect(cfg.siem.syslogPort).toBe(514);
    expect(cfg.siem.syslogProto).toBe('udp');
  });

  it('SIEM enabled + syslog mode + missing host → valid=false + ERROR emitted', () => {
    process.env.QODIQA_LOGSHIP_SIEM_ENABLED = 'true';
    process.env.QODIQA_LOGSHIP_SIEM_MODE    = 'syslog';
    const cfg = loadLogShipConfig();
    expect(cfg.siem.valid).toBe(false);
    expect(emit).toHaveBeenCalledWith('ERROR', 'LOGSHIP_CONFIG_INVALID',
      expect.objectContaining({ destination: 'siem', mode: 'syslog' }),
    );
  });

  it('falls back to ALERT_SIEM_* variables when QODIQA_LOGSHIP_SIEM_* is unset', () => {
    process.env.QODIQA_LOGSHIP_SIEM_ENABLED = 'true';
    process.env.ALERT_SIEM_URL = 'https://alert-siem.company.com';
    const cfg = loadLogShipConfig();
    expect(cfg.siem.url).toBe('https://alert-siem.company.com');
    expect(cfg.siem.valid).toBe(true);
  });

  it('QODIQA_LOGSHIP_SIEM_* takes precedence over ALERT_SIEM_*', () => {
    process.env.QODIQA_LOGSHIP_SIEM_ENABLED = 'true';
    process.env.QODIQA_LOGSHIP_SIEM_URL = 'https://bulk-siem.company.com';
    process.env.ALERT_SIEM_URL          = 'https://alert-siem.company.com';
    const cfg = loadLogShipConfig();
    expect(cfg.siem.url).toBe('https://bulk-siem.company.com');
  });
});

describe('loadLogShipConfig — global settings', () => {
  let savedEnv;

  beforeEach(() => {
    savedEnv = { ...process.env };
    jest.clearAllMocks();
  });

  afterEach(() => {
    Object.keys(process.env).forEach(k => { if (!(k in savedEnv)) delete process.env[k]; });
    Object.assign(process.env, savedEnv);
  });

  it('maxRetries defaults to 3', () => {
    delete process.env.QODIQA_LOGSHIP_MAX_RETRIES;
    expect(loadLogShipConfig().maxRetries).toBe(3);
  });

  it('maxRetries reads from QODIQA_LOGSHIP_MAX_RETRIES', () => {
    process.env.QODIQA_LOGSHIP_MAX_RETRIES = '5';
    expect(loadLogShipConfig().maxRetries).toBe(5);
  });

  it('returned config is frozen', () => {
    const cfg = loadLogShipConfig();
    expect(Object.isFrozen(cfg)).toBe(true);
  });

  it('maxQueueDepth defaults to 10000', () => {
    delete process.env.QODIQA_LOGSHIP_MAX_QUEUE_DEPTH;
    expect(loadLogShipConfig().maxQueueDepth).toBe(10_000);
  });

  it('maxQueueDepth reads from QODIQA_LOGSHIP_MAX_QUEUE_DEPTH', () => {
    process.env.QODIQA_LOGSHIP_MAX_QUEUE_DEPTH = '500';
    expect(loadLogShipConfig().maxQueueDepth).toBe(500);
  });
});
