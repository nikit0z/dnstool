#!/usr/bin/python

import requests
import argparse
import sys
import json
import re

api_key = '' 
api_url = ''

parser = argparse.ArgumentParser()

parser.add_argument('--action',
                    metavar='action',
                    help='Action (add/delete)',
                    required=True)

parser.add_argument('--fqdn',
                    metavar='fqdn',
                    help='Record fqdn',
                    required=True)

parser.add_argument('--type',
                    metavar='type',
                    help='Record type (A/PTR/A,PTR/CNAME)',
                    required=True)

parser.add_argument('--value',
                    metavar='value',
                    help='Record value',
                    required=True)

parser.add_argument('--ttl',
                    metavar='ttl',
                    help='Record ttl',
                    required=False,
                    default=3600)

args = parser.parse_args()


def check_ip(ip):
    regex_ip = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    if not regex_ip.match(ip):
        print_error(ip + ' does not look like correct ip')


def check_domain(domain):
    regex_domain = re.compile('([a-z\-0-9]+\.)?([a-z\-0-9]+)\.([a-z]+)$', re.IGNORECASE)
    if not regex_domain.match(domain):
        print_error(domain + ' does not look like correct domain')


def check_ptr(ptr):
    regex_ptr = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\.in-addr\.arpa$', re.IGNORECASE)
    if not regex_ptr.match(ptr):
        print_error(ptr + ' does not look like correct ptr')


def print_error(message):
    print message
    sys.exit(1)


def validate_variables():
    if args.type == 'A' or args.type == 'A,PTR':
        check_domain(args.fqdn)
        check_ip(args.value)
    elif args.type == 'PTR':
        check_ptr(args.fqdn)
        check_domain(args.value)
    elif args.type == 'CNAME':
        check_domain(args.fqdn)
        check_domain(args.value)
    else:
        print_error('This record type is not supported yet')


def get_domain_name(record_type, fqdn):
    if record_type == 'PTR':
        domain = fqdn.split('.', 1)[1]
    else:
        domain = '.'.join(fqdn.split('.')[-2:])
    return domain


def record_exists(domain, fqdn):
    json_responce = json.loads(api_request('GET', domain, {}))
    for record in json_responce['records']:
        if record['name'] == fqdn:
            return True
    return False


def api_request(req_type, req_url, payload):
    timeout = 30
    headers = {'X-API-Key': api_key}
    try:
        if req_type == 'GET':
            responce = requests.get(api_url + req_url, headers=headers, timeout=timeout)
        elif req_type == 'PATCH':
            responce = requests.patch(api_url + req_url, headers=headers, data=payload, timeout=timeout)
        responce.raise_for_status()
        if responce.text == 'Bad Request':
            raise requests.RequestException('Bad request')
        elif responce.text.startswith('{"error"'):
            raise requests.RequestException(responce.text)
    except requests.HTTPError, error:
        print_error(error)
    except requests.RequestException, error:
        print_error(error)
    return responce.text


def build_payload(fqdn, record, record_type, change_type):
    payload = '''{{"rrsets": [ {{"name": "{fqdn}",
                                 "type": "{type}",
                                 "changetype": "{change_type}",
                                 "records": [ {record} ] }} ] }}'''.format(fqdn=fqdn,
                                                                           type=record_type,
                                                                           change_type=change_type,
                                                                           record=record)
    return payload


def add_record(domain):
    record_type = args.type
    set_ptr = 'false'  # pdns api doesn't accept boolean (

    if record_exists(domain, args.fqdn):
        print_error('This DNS record already exists')
    else:
        change_type = 'REPLACE'

    if record_type == 'A,PTR':
        if not record_exists(domain, args.fqdn):
            set_ptr = 'true'
        record_type = 'A'

    record = '''{{"content": "{value}",
                   "disabled": false,
                   "name": "{fqdn}",
                   "ttl": {ttl},
                   "type": "{type}",
                   "set-ptr": {set_ptr} }}'''.format(fqdn=args.fqdn,
                                                      type=record_type,
                                                      value=args.value,
                                                      ttl=args.ttl,
                                                      set_ptr=set_ptr)

    payload = build_payload(args.fqdn, record, record_type, change_type)
    api_request('PATCH', domain, payload)
    if record_exists(domain, args.fqdn):
        print 'Change was done succesfully'
    else:
        print_error('Something went wrong')


def del_record(domain):
    record_type = args.type
    if record_exists(domain, args.fqdn):
        change_type = 'DELETE'
    else:
        print_error('This DNS record doesn\'t exist')

    if record_type == 'A,PTR':
        ptr_fqdn = '.'.join(reversed(args.value.split('.'))) + '.in-addr.arpa'
        ptr_domain = get_domain_name('PTR', ptr_fqdn)

        if record_exists(ptr_domain, ptr_fqdn):
            payload = build_payload(ptr_fqdn, '', 'PTR', change_type)
            api_request('PATCH', ptr_domain, payload)

    if record_type == 'A,PTR':
        record_type = 'A'

    payload = build_payload(args.fqdn, '', record_type, change_type)
    api_request('PATCH', domain, payload)
    if not record_exists(domain, args.fqdn):
        print 'Change was done succesfully'
    else:
        print_error('Something went wrong')


def main():
    validate_variables()

    domain = get_domain_name(args.type, args.fqdn)

    if args.action == 'add':
        add_record(domain)
    elif args.action == 'delete':
        del_record(domain)
    else:
        print_error('Action is not supported')


if __name__ == '__main__':
    main()
