#!/usr/bin/env python3
import unittest
import logging
import re
from publicsuffixlist import PublicSuffixList


def decompose_filter(inputstring, psl=PublicSuffixList()):
    logging.debug(f'Parsing "{inputstring}"')
    try:
        match_list = []
        querystring = inputstring
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


class TestExtractQuery(unittest.TestCase):

    def test_simple_query(self):
        expected_dict = {'querystring': 'www.example.com.evil.com', 'ts_q1': 'www.example.com.evil.com', 'ts_q2': 'www.example.com.evil.com'}
        self.assertEqual(decompose_filter('www.example.com.evil.com'), expected_dict)

    def test_failed_mid_strings(self):
        self.assertIsNone(decompose_filter('%adgoogl%'))

    def test_failed_partial_domain(self):
        self.assertIsNone(decompose_filter('%vil.com'))

    def test_clean_and_trailing(self):
        expected_dict = {'ts_q1': 'evil.co.uk', 'ts_q2': 'evil.co.uk', 'querystring': '%.evil.co.uk'}
        self.assertEqual(decompose_filter('%[.]evil.co.uk'), expected_dict)

    def test_leading_sub(self):
        expected_dict = {'querystring': 'www.example.com.%', 'ts_q1': 'www.example.com.:*', 'ts_q2': 'www.example.com.:*'}
        self.assertEqual(decompose_filter('www.example.com.%'), expected_dict)

    def test_only_www(self):
        expected_dict = {'ts_q1': 'www:*', 'ts_q2': 'www:*', 'querystring': 'www%'}
        self.assertEqual(decompose_filter('www%'), expected_dict)

    def test_trailing(self):
        expected_dict = {'ts_q1': 'evil.co.uk', 'ts_q2': 'evil.co.uk', 'querystring': '%.evil.co.uk'}
        self.assertEqual(decompose_filter('%[.]evil.co.uk'), expected_dict)

    def test_trailing_multiple_wildcard(self):
        expected_dict = {'ts_q1': 'evil.co.uk', 'ts_q2': 'evil.co.uk', 'querystring': '%.%.evil.co.uk'}
        self.assertEqual(decompose_filter('%.%.evil.co[.]uk'), expected_dict)

    def test_www_multiple_wildcard(self):
        expected_dict = {'ts_q1': 'www.:*', 'ts_q2': 'www.:*', 'querystring': 'www.%.%'}
        self.assertEqual(decompose_filter('www.%.%'), expected_dict)

    def test_ignore_public_suffix(self):
        expected_dict = {'querystring': 'www.example%.co.uk', 'ts_q1': 'www.example:*', 'ts_q2': 'www.example:*'}
        self.assertEqual(decompose_filter('www.example%.co.uk'), expected_dict)

    def test_get_all_domains(self):
        expected_dict = {'ts_q1': 'example.co.:*', 'ts_q2': 'example.co.:*', 'querystring': '%.example.co.%'}
        self.assertEqual(decompose_filter('%.example.co.%'), expected_dict)


if __name__ == '__main__':
    unittest.main()
