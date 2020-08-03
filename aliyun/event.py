# -*- coding: utf-8 -*-

import logging
import os
import json
import dataway
import time
import sys


def handler_ecs(evt, dw):
    if not isinstance(evt, dict):
        raise ValueError("event should be dict, got '%s'" % type(evt))
    eventid = ''
    source = evt.get('product')
    status = evt.get('level')
    if status == 'CRITICAL':
        status = 'critical'
    elif status == 'WARN':
        status = 'warning'
    else:
        status = 'info'
    title = evt.get('name')
    region = evt.get('regionId', '')
    content = evt.get('content')
    content_str = ''
    event_type = ''
    tags = dict()
    if isinstance(content, dict):
        tags = dataway.json_copy(content)
        tags['regionId'] = region
        event_type = content.get('eventType', '')
        eventid = content.get('eventId', '')
        content_str = json.dumps(content)
    dw.write_keyevent(title=title, source=source, event_id=eventid, type_=event_type, status=status, content=content_str,
                      tags=tags, timestamp=time.time())


def handler(event, context):
    debug = os.getenv('DEBUG_MODE')
    log_level = logging.WARNING
    if debug == '1' or debug == 'True':
        log_level = logging.DEBUG
    logging.basicConfig(level=log_level)
    logging.getLogger().setLevel(level=log_level)
    logging.debug('Python Version: %s' % sys.version)
    logging.debug('start handle event: %s' % event)
    dataway_url = os.getenv('DATAWAY_URL')
    if not dataway_url:
        logging.error('DATAWAY_URL must not be empty')
        return
    access_key = os.getenv('DATAWAY_ACCESS_KEY')
    secret_key = os.getenv('DATAWAY_SECRET_KEY')
    token = os.getenv('DATAWAY_TOKEN')
    rp = os.getenv('DATAWAY_RP')
    dw = dataway.DataWay(url=dataway_url, access_key=access_key, token=token, rp=rp, secret_key=secret_key)
    evt = json.loads(event)
    product = evt.get('product')
    if product == 'ECS':
        handler_ecs(evt, dw)
    else:
        logging.error("unsupport product '%s'" % product)
