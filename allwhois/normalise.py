"""
Normaliser
"""
__all__ = ["Normaliser", "_dedupe_list"]

import calendar
import functools
import json
import operator
import re
import string
import time
from datetime import datetime, timedelta
from typing import Union, List

template0 = {
    # Unified Key: [Keys from various sources]
    'domain_name': ['domainName', 'domain', 'domainname'],
    'domain_canonical_name': ['canonical_name'],
    'domain_created_date': ['domain_name_commencement_date', 'domain_created', 'createDate', 'createdDate', 'connected_date', 'registered', 'registered_date', 'created_on', 'registered_on', 'registration_time', 'domain_record_activated', 'entry_created', 'create_date', 'creation_date', 'record_created'],
    'domain_expiry_date': ['validity', 'valid_until', 'expiration_date', 'expire', 'expire_date', 'renewal_date', 'expiry_date', 'domain_expires', 'expired_date', 'paid_till', 'expires', 'expiration_time', 'expires_on', 'expiresDate', 'registry_expiry_date', 'expires_date', 'record_expires_on'],
    'domain_updated_date': ['updated_on', 'last_updated_on', 'updateDate', 'updatedDate', 'update_date', 'updated', 'entry_updated', 'domain_record_last_updated', 'modified', 'last_updated', 'updated_date', 'last_update', 'last_modified', 'record_last_updated_on'],
    'domain_name_servers': ['dns', 'servers', 'nserver', 'domain_servers', 'name_servers', 'name_server_', 'domain_servers_in_listed_order', 'name_servers_in_the_listed_order', 'name_server_information', 'nameserver', 'nameservers', 'name_server', 'dns_servers', 'name_servers_information'],
    'domain_status': ['epp_status', 'flags', 'domainStatus', 'registration_status', 'state', 'domain_status_', 'status', 'domain_status'],
    'contact_email': ['contactEmail'],
    'registrant_name': ['domain_owner', 'registrant', 'registrant_contact', 'organization', 'owner', 'owner_name'],
    'registrant_id': ['ownerid', 'org_id', 'owner_id'],
    'registrant_country_code': ['owner_country_code'],
    'registrant_email': ['owner_email'],
    'registrant_locality': ['owner_locality'],
    'registrant_locality_zipcode': ['owner_locality_zipcode'],
    'registrant_zipcode': ['owner_zipcode'],
    'registrant_type': ['organization_type'],
    'registrant_address': ['address_loc', 'descr', 'owner_address'],
    'registrar_name': ['domain_registrar_name', 'registrar', 'sponsoring_registrar_name', 'registrarName'],
    'registrar_id': ['sponsoring_registrar_pandi_id', 'sponsoring_registrar_id'],
    'registrar_city': ['sponsoring_registrar_city'],
    'registrar_state_province': ['sponsoring_registrar_state_province'],
    'registrar_organization': ['sponsoring_registrar_organization'],
    'registrar_zip': ['sponsoring_registrar_postal_code'],
    'registrar_country': ['sponsoring_registrar_country'],
    'registrar_telephone': ['sponsoring_registrar_phone'],
    'registrar_email': ['sponsoring_registrar_contact_email'],
    'registrar_whois_server': ['whoisServer', 'domain_registrar_whois'],
    'registrar_whois_url': ['domain_registrar_url'],
    'registrar_iana_id': ['IANAID', 'domain_registrar_id', 'registrarIANAID'],
    'admin_contact': ['administrative_contact', 'admin_c'],
    'tech_contact': ['technical_contact', 'tech_c', 'technical_contact_information'],
    'zone_contact': ['zone_c'],
    'domain_dnssec': ['dnssec'],
    'domain_dnssec_ds_data': ['dnssec_ds_data'],
}

sub_keys_template0 = {
    # sub keys
    'zip': ['postalCode', 'postal_code', 'zipcode'],
    'locality_zip': ['locality_zipcode'],
    'fax_ext': ['faxExt', 'fax_ext'],
    'telephone': ['phone'],
    'telephone_ext': ['telephoneExt', 'telephone_ext', 'phone_ext'],
    'address': ['street_address', 'address', 'contact'],
    'organization': ['company'],
}

dnssec_codes = [
    "no", "unsigned", "signedDelegation", "unsigned delegation"
]

epp_codes = {
    'active': ['ACTIVE'],
    'inactive': ['INACTIVE'],
    'ok': ['OK'],
    'linked': ['LINKED'],
    'addPeriod': ['ADD PERIOD'],
    'autoRenewPeriod': ['AUTO RENEW PERIOD', 'AUTORENEWPERIOD'],
    'pendingCreate': ['PENDING CREATE', 'PENDINGCREATE'],
    'pendingDelete': ['PENDING DELETE', 'PENDINGDELETE'],
    'pendingRenew': ['PENDING RENEW', 'PENDINGRENEW'],
    'pendingRestore': ['PENDING RESTORE', 'PENDINGRESTORE'],
    'pendingUpdate': ['PENDING UPDATE', 'PENDINGUPDATE'],
    'redemptionPeriod': ['REDEMPTION PERIOD', 'REDEMPTIONPERIOD'],
    'renewPeriod': ['RENEW PERIOD', 'RENEWPERIOD'],
    'updateProhibited': ['Update forbidden'],
    'serverDeleteProhibited': ['SERVER DELETE PROHIBITED', 'SERVERDELETEPROHIBITED', 'Deletion forbidden'],
    'serverHold': ['SERVER HOLD', 'SERVERHOLD'],
    'serverRenewProhibited': ['SERVER RENEW PROHIBITED'],
    'serverTransferProhibited': ['SERVER TRANSFER PROHIBITED'],
    'serverUpdateProhibited': ['SERVER UPDATE PROHIBITED', 'Sponsoring registrar change forbidden'],
    'transferPeriod': ['TRANSFER PERIOD'],
    'transferLocked': ['TRANSFER LOCKED'],
    'clientHold': ['CLIENT HOLD'],
    'clientDeleteProhibited': ['CLIENT DELETE PROHIBITED', 'DELETE PROHIBITED'],
    'clientTransferProhibited': ['CLIENT TRANSFER PROHIBITED', 'TRANSFER PROHIBITED'],
    'clientUpdateProhibited': ['CLIENT UPDATE PROHIBITED', 'UPDATE PROHIBITED', 'Registrant change forbidden'],
    'clientRenewProhibited': ['CLIENT RENEW PROHIBITED', 'RENEW PROHIBITED'],
    'Administratively blocked': ['Administratively blocked']
}
inverted_epp_dict = {val: key for key, arr in epp_codes.items() for val in arr}
epp_re = re.compile(
    "(" + '|'.join(list(inverted_epp_dict.keys())) + "|" + '|'.join(list(inverted_epp_dict.values())) + ")",
    re.MULTILINE | re.IGNORECASE
)

pop_these = [
    "query", "reg_name", "data_validation", "relevant_dates", "regnr", "disclaimer", "holder", "nsset",
    "connected_date", "changed", "free_date", "person", "fax_no", "phone", "nic_hdl", "address", "url",
    "source", "mnt_by", "dom_public", "country_loc", "organization_loc", "person_loc", "postal_code_loc",
    "created", "nic_hdl_br", "nslastaa", "nsstat", "owner_c", "outzone", "delete", "more_information_at_http",
    "pid", "in_zone", "register_your_domain_name_at_https", "notice", "under_the_terms_and_conditions_at_https",
    "idn_tag", "family_name", "given_name", "reseller", "status_information", "re_registration_status"
]

DATE_FORMATS = [
    # http://docs.python.org/library/datetime.html#strftime-strptime-behavior
    '%Y-%b-%d',                     # 2000-jan-02
    '%d-%B-%Y',                     # 02-january-2000
    '%d-%b-%Y',                     # 02-jan-2000
    '%d-%b-%y',                     # 02-jan-00
    '%d.%m.%Y',                     # 02.02.2000
    '%d/%m/%Y',                     # 01/06/2011
    '%Y-%m-%d',                     # 2000-01-02
    '%d-%m-%Y',                     # 02-01-2000
    '%Y.%m.%d',                     # 2000.01.02
    '%Y/%m/%d',                     # 2005/05/30
    'before %b-%Y',                 # before aug-1996
    '%Y.%m.%d %H:%M:%S',            # 2002.09.19 13:00:00
    '%Y%m%d %H:%M:%S',              # 20110908 14:44:51
    '%Y-%m-%d %H:%M:%S',            # 2011-09-08 14:44:51
    '%Y-%m-%d %H:%M:%S CLST',       # 2011-09-08 14:44:51 CLST CL
    '%Y-%m-%d %H:%M:%S.%f',         # 2011-09-08 14:44:51 CLST CL
    '%d.%m.%Y %H:%M:%S',            # 19.09.2002 13:00:00
    '%d-%b-%Y %H:%M:%S %Z',         # 24-Jul-2009 13:20:03 UTC
    '%d/%m/%Y %H:%M:%S',            # 30/10/2002 00:00:00
    '%Y/%m/%d %H:%M:%S (%z)',       # 2011/06/01 01:05:01 (+0900)
    '%Y-%m-%d %H:%M:%S (%z)',       # 2011/06/01 01:05:01 (+0900)
    '%Y/%m/%d %H:%M:%S%z',          # 2011/06/01 01:05:01+0900
    '%Y-%m-%d %H:%M:%S%z',          # 2011-06-01 01:05:01+0900
    '%Y/%m/%d %H:%M:%S %z',         # 2011/06/01 01:05:01 +0900
    '%Y-%m-%d %H:%M:%S %z',         # 2011-06-01 01:05:01 +0900
    '%Y/%m/%d %H:%M:%S:%f%z',       # 2011/06/01 01:05:01:00+0900
    '%Y-%m-%d %H:%M:%S:%f%z',       # 2011-06-01 01:05:01:00+0900
    '%Y/%m/%d %H:%M:%S.%f%z',       # 2011/06/01 01:05:01.00+0900
    '%Y-%m-%d %H:%M:%S.%f%z',       # 2011-06-01 01:05:01.00+0900
    '%Y/%m/%d %H:%M:%S',            # 2011/06/01 01:05:01
    '%a %b %d %H:%M:%S %Z %Y',      # Tue Jun 21 23:59:59 GMT 2011
    '%a %b %d %H:%M:%S %Y',         # tue feb 10 09:42:42 2004
    '%a %b %d %Y',                  # Tue Dec 12 2000
    '%Y-%m-%dT%H:%M:%S',            # 2007-01-26T19:10:31
    '%Y-%m-%dT%H:%M:%SZ',           # 2007-01-26T19:10:31Z
    '%Y-%m-%dt%H:%M:%S.%fz',        # 2007-01-26t19:10:31.00z
    '%Y-%m-%dT%H:%M:%S%z',          # 2011-03-30T19:36:27+0200
    '%Y-%m-%dT%H:%M:%S.%f%z',       # 2011-09-08T14:44:51.622265+03:00
    '%Y-%m-%dt%H:%M:%S.%f',         # 2011-09-08t14:44:51.622265
    '%Y-%m-%dt%H:%M:%S',            # 2007-01-26T19:10:31
    '%Y-%m-%dt%H:%M:%SZ',           # 2007-01-26T19:10:31Z
    '%Y-%m-%dt%H:%M:%S.%fz',        # 2007-01-26t19:10:31.00z
    '%Y-%m-%dt%H:%M:%S%z',          # 2011-03-30T19:36:27+0200
    '%Y-%m-%dt%H:%M:%S.%f%z',       # 2011-09-08T14:44:51.622265+03:00
    '%Y%m%d',                       # 20110908
    '%Y. %m. %d.',                  # 2020. 01. 12.
    'before %b-%Y',                 # before aug-1996
    '%a %d %b %Y',                  # Tue 21 Jun 2011
    '%A %d %b %Y',                  # Tuesday 21 Jun 2011
    '%a %d %B %Y',                  # Tue 21 June 2011
    '%A %d %B %Y',                  # Tuesday 21 June 2011
    '%Y-%m-%d %H:%M:%S (%Z+0:00)',  # 2007-12-24 10:24:32 (gmt+0:00)
    '%B %d %Y',                     # January 01 2000
]
date_fields = [
    'domain_created_date', 'domain_updated_date', 'domain_expiry_date', 'registrar_registration_expiration_date'
]
contact_fields = [
    'registrant_', 'admin_', 'tech_', 'billing_', 'zone_'
]


def flatten(lst: list) -> List:
    """flatten the list of lists.
    :param lst: list of lists
    :return: flattened list
    """
    return functools.reduce(operator.iconcat, lst, [])


def _dedupe_list(lst: list) -> List:
    """case insensitive/fuzzy removal of duplicates or similarities from a list.
    :param lst: list of items
    :return: de-duplicated list of items
    """
    marker = set()
    lst = flatten(lst) if any(isinstance(el, list) for el in lst) else lst
    lst = list(filter(None, lst))
    result = [
        not marker.add(x.replace("www.", "").translate(
            str.maketrans('', '', string.punctuation)
        ).casefold()) and x
        for x in lst
        if x.replace("www.", "").translate(
            str.maketrans('', '', string.punctuation)
        ).casefold() not in marker
    ]
    return list(filter(None, result))


def _dedupe_dates(lst: list, precision: str = "day", tz_aware: bool = False) -> List:
    """Dedupe a given list of date objects
    :param lst: list of date objects
    :param precision: "day" to dedupe upto day (y/m/d) or "time" for y/m/d h:m:s
    :param tz_aware: If true, then dedupe keeping timezones information
    """
    dates_dict = {}
    k = None
    for dt in lst:
        if tz_aware:
            if not dt.tzinfo:
                timestamp = calendar.timegm(dt.timetuple())
                k = datetime.utcfromtimestamp(timestamp)
            else:
                timestamp = time.mktime(dt.timetuple())
                k = datetime.fromtimestamp(timestamp)
        else:
            if precision == "day":
                k = datetime(dt.year, dt.month, dt.day).timestamp()
            elif precision == "time":
                k = datetime(dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second).timestamp()

        dates_dict.update({k: dt})

    return list(dates_dict.values())


class UnknownDateFormat(Exception):
    """Custom Exception."""
    pass


class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (datetime, datetime.date, datetime.time)):
            return obj.isoformat()
        elif isinstance(obj, timedelta):
            return (datetime.min + obj).time().isoformat()

        return super(DateTimeEncoder, self).default(obj)


class Normaliser:

    date_as_string: bool = None

    def __setattr__(self, name, value):
        if name == 'date_as_string':
            super(Normaliser, self).__setattr__(name, value)

    @staticmethod
    def _group_keys(data: dict) -> dict:
        """Group certain keys together.
        :param data: dict to which the template needs to be applied
        :return: grouped keys dict
        """
        keys_to_group = (
            "registry_", "registrar_", "registrant_", "domain_", "admin_",
            "tech_", "billing_", "zone_", "option_", "company_"
        )
        for key in pop_these:
            # remove keys that are not necessary
            # they are still available in the z_raw key
            data.pop(key, None)

        # group the keys
        grouped = {}
        for key, value in data.items():
            if key.startswith(keys_to_group):
                new_key, sub_key = key.split("_", 1)
                if f"{new_key}_info" in grouped:
                    grouped[f"{new_key}_info"].update({sub_key: value})
                else:
                    grouped.update({f"{new_key}_info": {sub_key: value}})
            else:
                grouped.update({key: value})
        return grouped

    def _organise(self, data: dict) -> dict:
        """Organise & map the data appropriately.
        :param data: data dict
        :return: organised data dict
        """
        def _no_http(var):
            if var.startswith('http'):
                return False
            else:
                return True

        if 'domain_name' in data:
            if isinstance(data.get('domain_name'), list):
                data['domain_name'] = ', '.join(_dedupe_list(data.get('domain_name')))
        else:
            data['domain_name'] = ''
        if 'company_name' in data:
            if isinstance(data.get('company_name'), list):
                data['company_name'] = ', '.join(_dedupe_list(data.get('company_name')))
        if 'domain_dnssec' in data:
            if isinstance(data.get('domain_dnssec'), list):
                data['domain_dnssec'] = ', '.join(_dedupe_list(data.get('domain_dnssec')))
        if 'domain_name_servers' in data:
            if isinstance(data.get('domain_name_servers'), list):
                data['domain_name_servers'] = _dedupe_list(data.get('domain_name_servers'))
            elif isinstance(data.get('domain_name_servers'), str):
                data['domain_name_servers'] = data.get('domain_name_servers').split(' ')
            data['domain_name_servers'] = list(filter(None, data['domain_name_servers']))
            data['domain_name_servers'] = [
                ' ('.join([i.strip() for i in ns.split('\t')])+')'
                if '\t' in ns.strip() else ns
                for ns in data['domain_name_servers']
            ]
        if 'email' in data:
            if isinstance(data.get('email'), list):
                data['email'] = ', '.join(_dedupe_list(data.get('email')))
        if 'domain_status' in data:
            if isinstance(data.get('domain_status'), list):
                data['domain_status'] = flatten([i.split() for i in _dedupe_list(data.get('domain_status'))])
            elif isinstance(data.get('domain_status'), str):
                data['domain_status'] = data['domain_status'].split()
            data['domain_status'] = ' '.join(list(filter(_no_http, data['domain_status'])))
            data['domain_status'] = re.findall(epp_re, data['domain_status'])
        if 'domain_created_date' in data:
            if isinstance(data.get('domain_created_date'), list):
                data['domain_created_date'] = _dedupe_dates(data.get('domain_created_date'))
                if len(data['domain_created_date']) == 1:
                    data['domain_created_date'] = data['domain_created_date'][0]
        if 'domain_expiry_date' in data:
            if isinstance(data.get('domain_expiry_date'), list):
                data['domain_expiry_date'] = _dedupe_dates(data.get('domain_expiry_date'))
                if len(data['domain_expiry_date']) == 1:
                    data['domain_expiry_date'] = data['domain_expiry_date'][0]
        if 'domain_updated_date' in data:
            if isinstance(data.get('domain_updated_date'), list):
                data['domain_updated_date'] = _dedupe_dates(data.get('domain_updated_date'))
                if len(data['domain_updated_date']) == 1:
                    data['domain_updated_date'] = data['domain_updated_date'][0]
                elif len(data['domain_updated_date']) > 1:
                    data['domain_updated_date'] = max([str(d) for d in data['domain_updated_date']])
        if 'registrar_abuse_contact_email' in data:
            if isinstance(data.get('registrar_abuse_contact_email'), list):
                data['registrar_abuse_contact_email'] = ', '.join(_dedupe_list(data['registrar_abuse_contact_email']))
        if 'registrar_abuse_contact_phone' in data:
            if isinstance(data.get('registrar_abuse_contact_phone'), list):
                data['registrar_abuse_contact_phone'] = ', '.join(_dedupe_list(data['registrar_abuse_contact_phone']))
        if 'registrar_iana_id' in data:
            if isinstance(data.get('registrar_iana_id'), list):
                data['registrar_iana_id'] = ', '.join(_dedupe_list(data['registrar_iana_id']))
        if 'registrar_name' in data:
            if isinstance(data.get('registrar_name'), list):
                data['registrar_name'] = ', '.join(_dedupe_list(data['registrar_name']))
        if 'registrar_url' in data:
            if isinstance(data.get('registrar_url'), list):
                data['registrar_url'] = ', '.join(_dedupe_list(data['registrar_url']))
        if 'registrar_whois_server' in data:
            if isinstance(data.get('registrar_whois_server'), list):
                data['registrar_whois_server'] = ', '.join(_dedupe_list(data['registrar_whois_server']))
        if 'registry_domain_id' in data:
            if isinstance(data.get('registry_domain_id'), list):
                data['registry_domain_id'] = ', '.join(_dedupe_list(data['registry_domain_id']))
        if 'admin_street' in data:
            if isinstance(data.get('admin_street'), list):
                data['admin_street'] = ''.join(flatten(data.get('admin_street')))
        if 'billing_street' in data:
            if isinstance(data.get('billing_street'), list):
                data['billing_street'] = ''.join(flatten(data.get('billing_street')))
        if 'tech_street' in data:
            if isinstance(data.get('tech_street'), list):
                data['tech_street'] = ''.join(flatten(data.get('tech_street')))
        if 'registrant_street' in data:
            if isinstance(data.get('registrant_street'), list):
                data['registrant_street'] = ''.join(flatten(data.get('registrant_street')))
        if 'city' in data:
            if isinstance(data.get('city'), list):
                data['city'] = ', '.join(_dedupe_list(data['city']))
        if 'country' in data:
            if isinstance(data.get('country'), list):
                data['country'] = ', '.join(_dedupe_list(data['country']))

        if 'domain_created_date' not in data:
            data['domain_created_date'] = ''
        if 'domain_expiry_date' not in data:
            data['domain_expiry_date'] = ''
        if 'domain_updated_date' not in data:
            data['domain_updated_date'] = ''
        if 'domain_status' not in data:
            data['domain_status'] = []

        for addr in contact_fields:
            address = []
            postal = None
            if f'{addr}street' in data:
                if isinstance(data[f'{addr}street'], list):
                    data[f'{addr}street'] = ', '.join(_dedupe_list(data[f'{addr}street']))
                address.append(data[f'{addr}street'].strip())
            if f'{addr}state_province' in data:
                if isinstance(data[f'{addr}state_province'], list):
                    data[f'{addr}state_province'] = ', '.join(_dedupe_list(data[f'{addr}state_province']))
                address.append(data[f'{addr}state_province'].strip())
            if f'{addr}postal_code' in data:
                if isinstance(data[f'{addr}postal_code'], list):
                    data[f'{addr}postal_code'] = ', '.join(_dedupe_list(data[f'{addr}postal_code']))
                postal = data[f'{addr}postal_code'].strip()
            if f'{addr}country' in data:
                if isinstance(data[f'{addr}country'], list):
                    data[f'{addr}country'] = ', '.join(_dedupe_list(data[f'{addr}country']))
                address.append(f"{data[f'{addr}country'].strip()} {postal if postal else ''}".strip())
            if f'{addr}phone' in data:
                if isinstance(data[f'{addr}phone'], list):
                    data[f'{addr}phone'] = ', '.join(_dedupe_list(data[f'{addr}phone']))
                ph = data[f'{addr}phone'].strip()
                if ph:
                    address.append(f"Phone: {ph}")
            if f'{addr}fax' in data:
                if isinstance(data[f'{addr}fax'], list):
                    data[f'{addr}fax'] = ', '.join(_dedupe_list(data[f'{addr}fax']))
                fax = data[f'{addr}fax'].strip()
                if fax:
                    address.append(f"Fax: {fax}")

            if addr in '\t'.join(list(data.keys())):
                if f'{addr}address' not in data:
                    # if the address field is not there
                    data[f'{addr}address'] = ', '.join(list(filter(None, address)))
                elif not data[f'{addr}address']:
                    # if the address field is there, but empty
                    data[f'{addr}address'] = ', '.join(list(filter(None, address)))

        return data

    def _apply_template(self, data: dict, template: dict) -> dict:
        """Use a template to normalise/unify the keys of the data dict.
        :param data: input dict to which the template needs to be applied
        :param template: template dict to apply normalisation on data
        :return: template applied unified dict
        """
        result = {}
        for key, value in data.items():
            if isinstance(value, dict):
                result[key] = self._apply_template(value, template)
            else:
                new_key = ([x for x in template if key in template[x]] or [key])[0]
                result[new_key] = value

        return result

    def _standardise_dates(self, data: dict) -> dict:
        """Normalise all available date fields.
        :param data: data dict
        :return: date normalised data dict
        """
        def _tz_check(dt: str) -> str:
            match = [m.start() for m in re.finditer(r'\+|\-+', dt) if m.start() >= 15]
            if len(match) == 1:
                tz_len = len(dt[match[0]+1:])
                if tz_len <= 2:
                    dt = f"{dt}00"
            return dt

        def _to_std_date(val: str) -> Union[str, datetime]:
            val = val.lower().replace('(jst)', '(+0900)')
            val = re.sub(r"(\+[0-9]{2}):([0-9]{2})", r"\1\2", val)
            val = re.sub(r"(\ #.*)", "", val)
            val = re.sub(r"(\d+)(st|nd|rd|th) ", r"\1 ", val)
            val = _tz_check(val)
            for fmt in DATE_FORMATS:
                try:
                    _standardised_date = datetime.strptime(val, fmt)
                    return _standardised_date
                except ValueError:
                    pass

            raise UnknownDateFormat(f"Unknown date format: '{val}'")

        for field in date_fields:
            if field in data:
                if isinstance(data[field], list):
                    data[field] = [_to_std_date(dt) for dt in data[field]]
                elif isinstance(data[field], str):
                    if data[field]:
                        data[field] = _to_std_date(data[field])

        return data

    def normalise(self, dossier: dict):
        """Normalisation of the given input data.
        :param dossier: input data
        :return:
        """
        # normalise the data dict with unified keys
        normalised = self._apply_template(dossier, template0)
        # normalise all the date fields
        date_normalised = self._standardise_dates(normalised)
        # organise the data
        organised = self._organise(date_normalised)
        # group the keys in the dict
        normalised = self._group_keys(organised)
        # reapply template for the grouped sub-keys
        normalised = self._apply_template(normalised, sub_keys_template0)

        if self.date_as_string:
            normalised = json.loads(DateTimeEncoder().encode(normalised))

        return normalised
