#!/usr/bin/env python3
import json
import logging
import random
import string
import re
from datetime import date, datetime, timedelta

import psycopg2
from psycopg2.extras import RealDictCursor

from publicsuffixlist import PublicSuffixList


def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError("Type %s not serializable" % type(obj))


class CrtSh:
    """ Search crt.sh for certificates of interest """

    def __init__(self):
        self.psl = PublicSuffixList()
        self.valid_start_lowerlimit = date.today() - timedelta(days=365)
        self.valid_start_upperlimit = date.today() + timedelta(days=5)
        self.issuer_filter = "%"
        self._named_statement = "CERTFILTER_" + ''.join(random.choices(string.ascii_uppercase, k=8))
        self.sql_shell = """
PREPARE {named_statement} AS
WITH ci AS (
  SELECT min(sub.CERTIFICATE_ID) ID,
         min(sub.ISSUER_CA_ID) ISSUER_CA_ID,
         array_agg(DISTINCT sub.NAME_VALUE) NAME_VALUES,
         x509_subjectName(sub.CERTIFICATE) SUBJECT_NAME,
         x509_notBefore(sub.CERTIFICATE) NOT_BEFORE,
         x509_notAfter(sub.CERTIFICATE) NOT_AFTER
    FROM (SELECT DISTINCT
              cai.CERTIFICATE_ID CERTIFICATE_ID,
              cai.ISSUER_CA_ID ISSUER_CA_ID,
              cai.NAME_VALUE NAME_VALUE,
              cai.CERTIFICATE CERTIFICATE
        FROM certificate ci, unnest(identities(certificate)),
              certificate_and_identities cai
        WHERE cai.CERTIFICATE_ID = ci.id
          AND lexeme ILIKE $1
          AND identities(ci.certificate) @@ $2
          AND identities(ci.certificate) @@ $3
          AND coalesce(x509_notBefore(cai.CERTIFICATE), 'infinity'::timestamp) >= $4 AT TIME ZONE 'UTC'
          AND coalesce(x509_notBefore(cai.CERTIFICATE), 'infinity'::timestamp) <= $5 AT TIME ZONE 'UTC'
      ) sub
    GROUP BY sub.CERTIFICATE
)
SELECT ci.ISSUER_CA_ID,
       ca.NAME ISSUER_NAME,
       ci.NAME_VALUES,
       ci.ID MIN_CERT_ID,
       le.MIN_ENTRY_TIMESTAMP,
       ci.NOT_BEFORE,
       ci.NOT_AFTER
  FROM ci
    LEFT JOIN LATERAL (
        SELECT min(ctle.ENTRY_TIMESTAMP) MIN_ENTRY_TIMESTAMP
            FROM ct_log_entry ctle
            WHERE ctle.CERTIFICATE_ID = ci.ID
    ) le ON TRUE, ca
  WHERE ci.ISSUER_CA_ID = ca.ID
    AND ca.NAME ILIKE lower($6)
  ORDER BY le.MIN_ENTRY_TIMESTAMP DESC;
""".format(named_statement=self._named_statement)
        self.sql_exec = """
EXECUTE {named_statement} (
  %(querystring)s,
  %(ts_q1)s,
  %(ts_q2)s,
  %(valid_from_lowerlimit)s,
  %(valid_from_upperlimit)s,
  %(issuer_filter)s
)
""".format(named_statement=self._named_statement)
        self._connect_certwatch()
        self._setup_cursor()

    def _connect_certwatch(self):
        self.conn = psycopg2.connect(dbname="certwatch", user="guest", host="crt.sh", cursor_factory=RealDictCursor)
        self.conn.set_session(readonly=True, autocommit=True)

    def _setup_cursor(self, dup=False):
        try:
            self.cur = self.conn.cursor()
        except psycopg2.InterfaceError:
            self._connect_certwatch()
            if not dup:
                self._setup_cursor(dup=True)
            else:
                raise

    def _prepare_statement(self, dup=False):
        try:
            self.cur.execute(self.sql_shell)
        except psycopg2.errors.DuplicatePreparedStatement:
            pass
        except psycopg2.InterfaceError:
            self._setup_cursor()
            if not dup:
                self._prepare_statement(dup=True)
            else:
                raise

    def getcerts(self, filter_list, error_limit=20, max_filters=1000, split_name_list=True):
        self._prepare_statement()
        error_count, count = (0,) * 2
        filter_dict = list(decompose_filter_list(filter_list))
        while len(filter_dict) > 0:
            if error_count >= error_limit or count >= max_filters:
                logging.error("stopping processing, generated {} errors".format(error_count))
                break
            count += 1
            item = ''
            try:
                item = filter_dict.pop()
                logging.debug('processing filter "{}" of {} remaining'.format(item, len(filter_dict)))
                if 'valid_from_lowerlimit' not in item:
                    item['valid_from_lowerlimit'] = self.valid_start_lowerlimit
                if 'valid_from_upperlimit' not in item:
                    item['valid_from_upperlimit'] = self.valid_start_upperlimit
                if 'issuer_filter' not in item:
                    item['issuer_filter'] = self.issuer_filter
                self.cur.execute(self.sql_exec, item)
                result = self.cur.fetchall()
                for cert in result:
                    if "name_values" in cert and split_name_list:
                        name_values = cert.pop('name_values')
                        for name_value in name_values:
                            cert['name_value'] = name_value
                            yield cert.copy()
                    else:
                        yield cert
            except psycopg2.errors.InvalidSqlStatementName:
                error_count += 1
                self._prepare_statement()
                filter_dict.insert(0, item)
            except Exception as e:
                logging.debug("Filter '{item}' raised exception: {e}".format(item=item, e=e))
                error_count += 1
                self._setup_cursor()
                filter_dict.insert(0, item)


def decompose_filter_list(inputlist):
    if isinstance(inputlist, str):
        inputlist = [inputlist]
    try:
        for inputstring in inputlist:
            assert isinstance(inputstring, str)
            filter_dict = decompose_filter(inputstring)
            if filter_dict:
                yield filter_dict
            else:
                continue
    except Exception as e:
        logging.error(f'Error on input list: "{e}"')


def decompose_filter(inputstring, psl=PublicSuffixList()):
    logging.debug(f'Parsing "{inputstring}"')
    try:
        match_list = []
        querystring = inputstring
        # Clean input
        querystring = re.sub(r'(?i)[^-a-z0-9.%_]', '', querystring).strip('. ').lower()
        logging.debug(f'Cleaned input to "{querystring}"')
        if '_' in querystring:
            logging.error(f'Single character wildcards are not handled yet. "{querystring}"')
        if querystring.count('%') == 0:
            ts_q1 = querystring
            ts_q2 = querystring
        else:
            # Check for usable strings at the start of the string
            leading_match = re.search(r'^(?P<q_lead>[-a-z0-9.]+)(?:[%_.]*[%_])', querystring)
            if leading_match:
                match_list.append(leading_match.group('q_lead') + ':*')
            # Check for usable strings in the middle of the string
            mid_match_list = re.findall(r'(?<=[%_]\.)(?P<q_mid>[-a-z0-9.]+)(?:[%_.]*[%_])', querystring)
            if mid_match_list:
                mid_match_list = [m + ':*' for m in mid_match_list]
                match_list.extend(mid_match_list)
            # Check for usable strings at the end of the string
            trailing_match = re.search(r'(?<=[%_]\.)(?P<q_trail>[-a-z0-9.]+[-a-z0-9])$', querystring)
            if trailing_match:
                if psl.is_private(trailing_match.group('q_trail')):
                    match_list.append(trailing_match.group('q_trail'))
            if match_list:
                match_list = list(set(match_list))
                match_list.sort(key=lambda x: len(x.lstrip('w').rstrip(':*')), reverse=True)
                ts_long_list = match_list[:2]
                ts_q1 = ts_long_list[0]
                ts_q2 = ts_long_list[-1]
            else:
                logging.error(f'Could not extract usable querystring on "{inputstring}"')
                return
    except Exception as e:
        logging.error(f'Error on "{inputstring}", "{e}"')
        return
    return_dict = {
        'querystring': querystring,
        'ts_q1': ts_q1,
        'ts_q2': ts_q2,
    }
    return return_dict


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('cert_filter', nargs=1, help='SQL filter for crt.sh certificate identity')
    parser.add_argument('issuer_filter', nargs='?', default="%", help='SQL filter for crt.sh certificate issuer')

    args = parser.parse_args()
    cert_filter = args.cert_filter[0]
    issuer_filter = args.issuer_filter

    crt_sh = CrtSh()
    crt_sh.issuer_filter = issuer_filter
    for cert_result in crt_sh.getcerts([cert_filter], split_name_list=False):
        print(json.dumps(cert_result, indent=2, default=json_serial))


if __name__ == "__main__":
    main()
