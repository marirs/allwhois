"""
Parse the text output
"""
__all__ = ["Parser"]

import re
from textwrap import dedent
from typing import Union

from .normalise import _dedupe_list

_patterns = {
    'delim_generic': re.compile(
        r"^(Last updated on|"
        r"Technical Contacts|"
        r"Admin Contact|"
        r"Nameservers|"
        r"Registrant|"
        r"Registrar|"
        r"address|"
        r"DNSSEC|"
        r"Holder|"
        r"Tech)"
        r"[^:]*$",
        re.MULTILINE | re.IGNORECASE
    ),
    'delim_sq': re.compile(r"(^(?:[a-z]\.\s+|)\[[^]]+\])", re.MULTILINE),
    'alpha_start': re.compile(r"^(\w\.\s)\["),
    'star_start': re.compile(f"(^\*+\s*[\w\-\/\t\.\(\)\\ ]+)(?=\:):", re.MULTILINE),
    'dotted_end': re.compile(r"([\w\-]+\.[\w\-]+\.[\w\-]+\.[\s$]|\:.*\.$)", re.MULTILINE),
    'non_email_val': re.compile(r"^(.*: please query the .*)\n?", re.MULTILINE | re.IGNORECASE),
    'ipv4or6': re.compile(r"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})|(([a-f0-9:]+:+)+[a-f0-9]+)"),
    'field': re.compile(r"(^[\w\-\/\t\'\.\(\) ]+)(?=\:):(?![0-9a-fA-F]{1,4}\:)", re.MULTILINE | re.IGNORECASE),
    'alt_field': re.compile(r"(^[^\t][\w\-\/\t\'\.\(\) ]+)[\\t]*(?=\:):(?![0-9a-fA-F]{1,4}\:)", re.MULTILINE | re.IGNORECASE),
    'key': re.compile(r"\s\w*~")
}
discard_prefix = (
    '#', "*", "-", "%", ">", "==", "url of", "for more information", "http", "web-based",
    "visit", "contact us", "protecting", "information", "whois ", "copyright", "in ",
    "markmonitor domain management", "protection according", "rules of", "estonia .ee"
)
discard_suffix = (
    ".", ","
)
discard_words = (
    "agreement",
)


class Parser:

    @staticmethod
    def _scrub(raw: str) -> str:
        """Scrub & Clean the given Raw Text.

        (1) remove paragraphs
        (2) remove indents
        (3) check for servers/server names ending with . and trim it
        (4) check for non email value in email field and remove it
        (5) check for fields not ending with delim ":" and add it
        (6) check for fields in square brackets and convert to normal fields
        :param raw: raw text as input
        :return: cleaned output as text string
        """
        def _word_count(string: str) -> int:
            """count the number of words in the given string."""
            return len(string.split())

        def _rm_dot(match: re.Match) -> str:
            """if any potential field having a . at the end."""
            if match.group(1).strip()[-1] == '.':
                val = match.group(1).strip()[:-1]
            else:
                val = match.group(1)
            return f'{val}'

        def _rm_star(match: re.Match) -> str:
            """if any potential field having a * at the beginning."""
            val = match.group(1)
            if val.startswith('*'):
                val = val.replace('*', '').strip()
            else:
                val = val[:-1]
            return f"{val}:"

        def _rm_delim_sq(match: re.Match) -> str:
            """if any potential field is surrounded with []."""
            val = match.group(1)
            if re.findall(_patterns.get('alpha_start'), val):
                # trim fields start with char. (eg: a. )
                val = val[2:].strip()
            val = val.replace('[', '').replace(']', '')
            val = f"{val}:"
            return val

        def _non_eml_val(match: re.Match) -> str:
            """if we dont have an email in a email field."""
            val = match.group(1).split(':', 1)
            if val:
                val = f"{val[0]}: \n"
            else:
                val = match.group(1)
            return val

        # remove indent from lines
        raw = "\n".join([dedent(line) for line in raw.splitlines() if line])
        # remove a "." if its a valid field, so they dont get scrubbed away
        raw = re.sub(_patterns.get('dotted_end'), _rm_dot, raw)
        # remove "*" at the beginning if its a valid field, so they dont get scrubbed away
        raw = re.sub(_patterns.get('star_start'), _rm_star, raw)
        # remove invalid email addresses from email field
        raw = re.sub(_patterns.get('non_email_val'), _non_eml_val, raw)
        output = "\n".join(
            [
                # remove all of the unwanted lines that is not needed
                # and keep only the domain result "field: value"
                line.strip()
                for line in raw.splitlines()
                if not line.lower().strip().startswith(discard_prefix)
                and not line.lower().strip().endswith(discard_suffix)
                and not set(discard_words).intersection(line.lower().strip().split())
                and not _word_count(line) >= 10
            ]
        )
        # check if generic fields dont have ":" and add the ":"
        output = re.sub(_patterns.get('delim_generic'), r"\1:", output)
        # remove square brackets and add the ":" delim
        output = re.sub(_patterns.get('delim_sq'), _rm_delim_sq, output)

        return output

    @staticmethod
    def _fixes(data: dict) -> dict:
        if 'created' in data:
            # move created to createDate, as created has
            # conflicts with different domains outputs
            if isinstance(data['created'], list):
                # if its a list, the 0th element has the original created date
                data['createDate'] = data['created'][0]
            else:
                data['createDate'] = data['created']

        if 'changed' in data:
            if isinstance(data['changed'], list):
                # some of the whois output has assigned inside of changed field
                # which holds the creation date of the domain. Look for it and extract
                c_dt = []
                u_dt = []
                for dt in data['changed']:
                    if dt.lower().endswith('(assigned)'):
                        c_dt.append(re.findall(r"\s\d+\s", dt)[0].strip())
                        if c_dt:
                            break
                    if 'not disclosed' not in dt.lower() and 'whois' not in dt.lower()\
                            and '@' not in dt.lower():
                        # otherwise get the update date from "changed"
                        u_dt.append(dt)

                if 'created' not in data:
                    # created date found and created was not in the data
                    data['createDate'] = c_dt
                else:
                    # created date found, but update only if
                    # original created date in data is empty
                    if not data['created']:
                        data['createDate'] = c_dt

                # updated date
                data['updateDate'] = u_dt
            else:
                if 'created' not in data:
                    # created date found and created was not in the data
                    data['createDate'] = data['changed']
                else:
                    if not data['created']:
                        # created date found, but update only if
                        # original created date in data is empty
                        data['createDate'] = data['changed']
        if 'registered' in data:
            data.pop('createDate', None)
            data.pop('created', None)

        if 'descr' in data:
            if isinstance(data['descr'], list):
                data['descr'] = ' '.join(data['descr'])
                if 'phone' in data:
                    if isinstance(data['phone'], list):
                        if len(data['phone']) >= 3:
                            data['descr'] = f"{data['descr']}. {data['phone'][0]} (Phone)"
                            data['phone'] = data['phone'][1:]
                if 'fax_no' in data:
                    if isinstance(data['fax_no'], list):
                        if len(data['fax_no']) >= 3:
                            data['descr'] = f"{data['descr']}, {data['fax_no'][0]} (Fax)"
                            data['fax_no'] = data['fax_no'][1:]

        if 'address_loc' in data:
            if isinstance(data['address_loc'], list):
                data['address_loc'] = ' '.join(_dedupe_list(data['address_loc']))

        if 'e_mail' in data:
            if isinstance(data['e_mail'], list):
                data['email'] = ', '.join([elem.replace(' AT ', '@') for elem in _dedupe_list(data['e_mail'])])
                data.pop('e_mail', None)

        if 'fax' in data:
            if isinstance(data['fax'], list):
                data['fax'] = ', '.join(_dedupe_list(data['fax']))

        if 'name_server' in data and 'domain_servers_in_listed_order' in data:
            if isinstance(data['name_server'], list):
                data['name_server'].append(data['domain_servers_in_listed_order'])
                data.pop('domain_servers_in_listed_order', None)
                data['name_server'] = [e for e in data['name_server'] if e != '.']
            elif isinstance(data['domain_servers_in_listed_order'], list):
                data['domain_servers_in_listed_order'].append(data['name_server'])
                data.pop('name_server', None)
                data['domain_servers_in_listed_order'] = [e for e in data['domain_servers_in_listed_order'] if e != '.']
            else:
                data['name_server'] += data['domain_servers_in_listed_order']
                data.pop('domain_servers_in_listed_order', None)

        return data

    def _to_dict(self, text: str) -> dict:
        """Convert the cleaned text into dict.
        :param text: the cleaned raw text
        :return: dict
        """
        def _repl(match: re.Match) -> str:
            """replace extracted matched groups and convert to valid dict keys format."""
            val = match.group(1).strip().lower()
            if re.findall(r"^\d", val):
                # if the assumed field starts
                # with a number/digit; ignore it
                return match.group(1)+":"

            val = val.replace(
                " ", "_").replace(
                "-", "_").replace(
                "/", "_").replace(
                ".", "").replace(
                "[", "").replace(
                "]", "").replace(
                "'s", "")
            return f'{val}~'

        dict_o = {}
        inline = " " + " ".join(
            [
                re.sub(_patterns.get('alt_field'), _repl, line)
                for line in text.splitlines()
            ]
        ).replace('not.defined', '')

        # get all the keys
        keys = re.findall(_patterns.get('key'), inline)
        # create the kv pair
        kv = zip(
            [
                key.replace(' ', '').replace('~', '').strip()
                for key in keys
            ],
            re.sub('|'.join(keys), '|', inline).split('|')[1:]
        )
        # add the values of similar keys into a list value for the key
        for k, v in kv:
            if k in dict_o:
                if isinstance(dict_o[k], list) and v not in dict_o[k]:
                    dict_o[k].append(v.strip())
                else:
                    if dict_o[k] != v:
                        dict_o[k] = [dict_o[k]] + [v.strip()]
            else:
                dict_o[k] = v.strip()

        dict_o = self._fixes(dict_o)
        return dict_o

    def parse(self, text: str) -> Union[dict, None]:
        """Parse the raw whois output into a desirable pretty dict."""
        raw_text = self._scrub(text)
        if raw_text:
            pretty = self._to_dict(raw_text)
        else:
            pretty = None
        return pretty
