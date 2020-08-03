# -*- coding: utf-8 -*-

import logging
import http.client
import urllib.parse
import hmac
from hashlib import md5, sha1
import base64
import json
from email.utils import formatdate
import time
import re
from collections import OrderedDict


METRIC_PATH = '/v1/write/metrics'
KEYEVENT_PATH = '/v1/write/keyevent'

MIN_ALLOWED_NS_TIMESTAMP = 1000000000000000000

ESCAPE_REPLACER = r'\\\1'
RE_ESCAPE_TAG_KEY = re.compile('([,= ])')
RE_ESCAPE_TAG_VALUE = RE_ESCAPE_TAG_KEY
RE_ESCAPE_FIELD_KEY = RE_ESCAPE_TAG_KEY
RE_ESCAPE_MEASUREMENT = re.compile('([, ])')
RE_ESCAPE_FIELD_STR_VALUE = re.compile('(["\\\\])')

KEYEVENT_STATUS = ('critical', 'error', 'warning', 'info', 'ok')

ASSERT_TYPE_MAPS = {
    'dict': {
        'type': (dict, OrderedDict),
        'message': 'should be a dict or OrderedDict'
    },
    'list': {
        'type': list,
        'message': 'should be a list',
    },
    'str': {
        'type': str,
        'message': 'should be a str',
    },
    'number': {
        'type': (int, float),
        'message': 'should be an int or float',
    },
    'int': {
        'type': int,
        'message': 'should be an int'
    }
}


def _assert_type(data, expected_type, name):
    if not isinstance(data, ASSERT_TYPE_MAPS[expected_type]['type']):
        e = Exception("'{0}' {1}, got {2}".format(name, ASSERT_TYPE_MAPS[expected_type]['message'], type(data)))
        raise e
    return data


def assert_dict(data, name):
    return _assert_type(data, 'dict', name)


def assert_str(data, name):
    return _assert_type(data, 'str', name)


def assert_number(data, name):
    return _assert_type(data, 'number', name)


def assert_int(data, name):
    return _assert_type(data, 'int', name)


def assert_list(data, name):
    return _assert_type(data, 'list', name)


def assert_enum(data, name, options):
    if data not in options:
        e = Exception('`{0}` should be one of {1}, got {2}'.format(name, ','.join(options), data))
        raise e
    return data


def assert_tags(data, name):
    assert_dict(data, name)
    for k, v in data.items():
        assert_str(k, 'Key of {0}:{1}'.format(name, k))
        assert_str(v, 'Value of {0}["{1}"]:{2}'.format(name, k, v))
    return data


def _ensure_binary(s, encoding='utf-8', errors='strict'):
    if isinstance(s, str):
        return s.encode(encoding, errors)
    elif isinstance(s, bytes):
        return s
    else:
        e = TypeError("not expecting type '%s'" % type(s))
        raise e


def _ensure_str(s, encoding='utf-8', errors='strict'):
    if not isinstance(s, (str, bytes)):
        e = TypeError("not expecting type '%s'" % type(s))
        raise e
    if isinstance(s, bytes):
        s = s.decode(encoding, errors)
    return s


def _convert_to_ns(timestamp=None):
    timestamp = timestamp or time.time()
    timestamp = int(timestamp)

    for i in range(3):
        if timestamp < MIN_ALLOWED_NS_TIMESTAMP:
            timestamp *= 1000
        else:
            break

    return timestamp


def json_copy(j):
    return json.loads(json.dumps(j))


def _get_body_md5(body=None):
    h = md5()
    h.update(_ensure_binary(body or ''))

    md5_res = h.digest()
    md5_res = base64.standard_b64encode(md5_res).decode()

    return md5_res


def _prepare_metric(data):
    assert_dict(data, name='data')

    measurement = assert_str(data.get('measurement'), name='measurement')

    tags = data.get('tags')
    if tags:
        assert_dict(tags, name='tags')
        assert_tags(tags, name='tags')

    fields = assert_dict(data.get('fields'), name='fields')

    timestamp = data.get('timestamp')
    if timestamp:
        assert_number(timestamp, name='timestamp')

    prepared_data = {
        'measurement': measurement,
        'tags': tags or None,
        'fields': fields or None,
        'timestamp': timestamp,
    }
    return prepared_data


# keyevent
def _prepare_keyevent(data):
    assert_dict(data, name='data')

    # Check Tags
    tags = data.get('tags') or {}
    assert_tags(tags, name='tags')

    # Tags.*
    alert_item_tags = data.get('alert_item_tags')
    if alert_item_tags:
        assert_tags(alert_item_tags, name='alert_item_tags')

        tags.update(alert_item_tags)

    # Tags.__eventId
    event_id = data.get('event_id')
    if event_id:
        tags['__eventId'] = assert_str(event_id, name='event_id')

    # Tags.__source
    source = data.get('source')
    if source:
        tags['__source'] = assert_str(source, name='source')

    # Tags.__status
    status = data.get('status')
    tags['__status'] = assert_enum(status, name='status', options=KEYEVENT_STATUS)

    # Tags.__ruleId
    rule_id = data.get('rule_id')
    if rule_id:
        tags['__ruleId'] = assert_str(rule_id, name='rule_id')

    # Tags.__ruleName
    rule_name = data.get('rule_name')
    if rule_name:
        tags['__ruleName'] = assert_str(rule_name, name='rule_name')

    # Tags.__type
    type_ = data.get('type')
    if type_:
        tags['__type'] = assert_str(type_, name='type')

    # Tags.__actionType
    action_type = data.get('action_type')
    if action_type:
        tags['__actionType'] = assert_str(action_type, name='action_type')

    # Check Fields
    fields = data.get('fields') or {}
    assert_dict(fields, name='fields')

    # Fields.__title
    fields['__title'] = assert_str(data.get('title'), name='title')

    # Fields.__content
    content = data.get('content')
    if content:
        fields['__content'] = assert_str(content, name='content')

    # Fields.__suggestion
    suggestion = data.get('suggestion')
    if suggestion:
        fields['__suggestion'] = assert_str(suggestion, name='suggestion')

    # Fields.__duration
    duration_ms = data.get('duration_ms')
    if duration_ms:
        assert_int(duration_ms, name='duration_ms')

    duration = data.get('duration')
    if duration:
        assert_int(duration, name='duration')

    # to ms
    if duration:
        duration = duration * 1000

    if duration_ms or duration:
        fields['__duration'] = (duration_ms or duration) * 1000

    # Fields.__dimensions
    dimensions = data.get('dimensions')
    if dimensions:
        dimensions = assert_list(data.get('dimensions'), name='dimensions')
        dimensions = sorted([_ensure_str(x) if isinstance(x, str) else str(x) for x in dimensions])
        dimensions = json.dumps(dimensions, ensure_ascii=False, separators=(',', ':'))
        fields['__dimensions'] = dimensions

    prepared_data = {
        'measurement': '__keyevent',
        'tags': tags,
        'fields': fields,
        'timestamp': data.get('timestamp'),
    }
    return _prepare_metric(prepared_data)


def _prepare_line_protocol(points):
    if not isinstance(points, (list, tuple)):
        points = [points]

    lines = []

    for p in points:
        # Influx DB line protocol
        # https://docs.influxdata.com/influxdb/v1.7/write_protocols/line_protocol_tutorial/
        measurement = p.get('measurement')
        measurement = re.sub(RE_ESCAPE_MEASUREMENT, ESCAPE_REPLACER, measurement)

        tag_set_list = []
        tags = p.get('tags') or None
        if tags:
            key_list = sorted(tags.keys())
            for k in key_list:
                v = tags[k]
                if not v:
                    continue

                k = re.sub(RE_ESCAPE_TAG_KEY, ESCAPE_REPLACER, k)
                v = re.sub(RE_ESCAPE_TAG_VALUE, ESCAPE_REPLACER, v)

                tag_set_list.append('{0}={1}'.format(_ensure_str(k), _ensure_str(v)))

        tag_set = ''
        if len(tag_set_list) > 0:
            tag_set = ',{0}'.format(','.join(tag_set_list))

        field_set_list = []
        fields = p.get('fields') or None
        if fields:
            key_list = sorted(fields.keys())
            for k in key_list:
                v = fields[k]
                if v is None:
                    continue

                k = re.sub(RE_ESCAPE_FIELD_KEY, ESCAPE_REPLACER, k)
                if isinstance(v, str):
                    v = re.sub(RE_ESCAPE_FIELD_STR_VALUE, ESCAPE_REPLACER, v)
                    v = '"{0}"'.format(_ensure_str(v))

                elif isinstance(v, bool):
                    v = '{0}'.format(v).lower()

                elif isinstance(v, int):
                    v = '{0}i'.format(v)

                else:
                    v = '{0}'.format(v)

                field_set_list.append('{0}={1}'.format(_ensure_str(k), _ensure_str(v)))

        field_set = ' {0}'.format(','.join(field_set_list))

        timestamp = p.get('timestamp')
        timestamp = _convert_to_ns(timestamp)
        timestamp = ' {0}'.format(timestamp)

        lines.append('{0}{1}{2}{3}'.format(_ensure_str(measurement), _ensure_str(tag_set), _ensure_str(field_set),
                                           _ensure_str(timestamp)))

    body = '\n'.join(lines)
    body = _ensure_binary(body)

    return body


class DataWay:
    def __init__(self, url=None, host=None, port=None, protocol=None, path=None, token=None, rp=None, timeout=None,
                 access_key=None, secret_key=None):
        self.host = host or 'localhost'
        self.port = int(port or 9528)
        self.protocol = protocol or 'https'
        self.path = path or '/v1/write/metrics'
        self.token = token
        self.rp = rp or None
        self.timeout = timeout or 3
        self.access_key = access_key
        self.secret_key = secret_key

        if url:
            splited_url = urllib.parse.urlsplit(url)

            if splited_url.scheme:
                self.protocol = splited_url.scheme

            if splited_url.path:
                self.path = splited_url.path

            if splited_url.query:
                parsed_query = urllib.parse.parse_qs(splited_url.query)
                if 'token' in parsed_query:
                    self.token = parsed_query['token'][0]

            if splited_url.netloc:
                host_port_parts = splited_url.netloc.split(':')
                if len(host_port_parts) >= 1:
                    self.host = host_port_parts[0]
                    if self.protocol == 'https':
                        self.port = 443
                    else:
                        self.port = 80

                if len(host_port_parts) >= 2:
                    self.port = int(host_port_parts[1])

    def write_metric(self, measurement, tags=None, fields=None, timestamp=None):
        data = {
            'measurement': measurement,
            'tags': tags,
            'fields': fields,
            'timestamp': timestamp,
        }

        # break obj reference
        data = json_copy(data)

        prepared_data = _prepare_metric(data)

        return self.post_line_protocol(points=prepared_data, path=METRIC_PATH, with_rp=True)

    def write_metrics(self, data):
        if not isinstance(data, (list, tuple)):
            e = Exception('`data` should be a list or tuple, got {0}'.format(type(data).__name__))
            raise e

        # break obj reference
        data = json_copy(data)

        prepared_data = []
        for d in data:
            prepared_data.append(_prepare_metric(d))

        return self.post_line_protocol(points=prepared_data, path=METRIC_PATH, with_rp=True)

    def write_keyevent(self, title, timestamp,
                       event_id=None, source=None, status=None, rule_id=None, rule_name=None, type_=None,
                       alert_item_tags=None, action_type=None,
                       content=None, suggestion=None, duration=None, duration_ms=None, dimensions=None,
                       tags=None, fields=None):
        data = {
            'title': title,
            'timestamp': timestamp,
            'event_id': event_id,
            'source': source,
            'status': status,
            'rule_id': rule_id,
            'rule_name': rule_name,
            'type': type_,
            'alert_item_tags': alert_item_tags,
            'action_type': action_type,
            'content': content,
            'suggestion': suggestion,
            'duration': duration,
            'duration_ms': duration_ms,
            'dimensions': dimensions,
            'tags': tags,
            'fields': fields,
        }

        # break obj reference
        data = json_copy(data)

        prepared_data = _prepare_keyevent(data)
        return self.post_line_protocol(points=prepared_data, path=KEYEVENT_PATH)

    def write_keyevents(self, data):
        if not isinstance(data, (list, tuple)):
            e = Exception('`data` should be a list or tuple, got {0}'.format(type(data).__name__))
            raise e

        # break obj reference
        data = json_copy(data)

        prepared_data = []
        for d in data:
            prepared_data.append(_prepare_keyevent(d))

        return self.post_line_protocol(points=prepared_data, path=KEYEVENT_PATH)

    def _get_sign(self, str_to_sign):
        h = hmac.new(_ensure_binary(self.secret_key), _ensure_binary(str_to_sign), sha1)

        sign = h.digest()
        sign = base64.standard_b64encode(sign).decode()

        return sign

    def _prepare_auth_headers(self, method, content_type=None, body=None):
        body = body or ''
        content_type = content_type or ''

        headers = {}
        if not self.access_key or not self.secret_key:
            return headers

        body_md5 = _get_body_md5(body)
        date_str = formatdate(timeval=None, localtime=False, usegmt=True)
        str_to_sign = '\n'.join([method, body_md5, content_type, date_str])

        sign = self._get_sign(str_to_sign)

        logging.debug('\n[String to sign] {0}'.format(json.dumps(str_to_sign)))
        logging.debug('[Signature] {0}'.format(json.dumps(sign)))

        headers['Date'] = date_str
        headers['Authorization'] = 'DWAY {0}:{1}'.format(self.access_key, sign)

        return headers

    def post_line_protocol(self, points, path=None, query=None, headers=None, with_rp=False):
        content_type = 'text/plain'

        # break obj reference
        points = json_copy(points)
        if query:
            query = json_copy(query)
        if headers:
            headers = json_copy(headers)

        body = _prepare_line_protocol(points)
        return self._do_post(path=path, body=body, content_type=content_type, query=query, headers=headers,
                             with_rp=with_rp)

    def _do_post(self, path, body, content_type, query=None, headers=None, with_rp=False):
        method = 'POST'
        path = path or self.path

        query = query or {}
        if self.token:
            query['token'] = self.token
        if with_rp and self.rp:
            query['rp'] = self.rp

        _auth_headers = self._prepare_auth_headers(method=method, content_type=content_type, body=body)

        headers = headers or {}
        headers.update(_auth_headers)
        headers['Content-Type'] = content_type

        return self._do_request(method=method, path=path, query=query, body=body, headers=headers)

    def _do_request(self, method=None, path=None, query=None, body=None, headers=None):
        method = method or 'GET'

        if query:
            path = path + '?' + urllib.parse.urlencode(query)

        logging.debug('[Request] {0} {1}://{2}:{3}{4}'.format(method, self.protocol, self.host, str(self.port), path))
        logging.debug('[Request Headers]\n{0}'.format(
            '\n'.join(['{0}: {1}'.format(k, v) for k, v in (headers or {}).items()]) or '<EMPTY>'))
        if method.upper() != 'GET':
            logging.debug('[Request Body]\n{0}'.format(_ensure_str(body or '') or '<EMPTY>'))

        resp_status_code = 0
        resp_raw_data = None
        resp_data = None

        conn = None
        if self.protocol == 'https':
            conn = http.client.HTTPSConnection(self.host, port=self.port, timeout=self.timeout)
        else:
            conn = http.client.HTTPConnection(self.host, port=self.port, timeout=self.timeout)

        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()

        resp_status_code = resp.status
        resp_raw_data = resp.read()

        resp_content_type = resp.getheader('Content-Type')
        if isinstance(resp_content_type, str):
            resp_content_type = resp_content_type.split(';')[0].strip()

        resp_data = resp_raw_data
        if resp_content_type == 'application/json':
            resp_data = json.loads(_ensure_str(resp_raw_data))

        logging.debug('[Response Code] {0}'.format(resp_status_code))
        logging.debug('[Response Body] {0}'.format(_ensure_str(resp_raw_data or '') or '<EMPTY>'))

        return resp_status_code, resp_data
