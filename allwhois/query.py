"""
python wrapper for linux whois
Requirements: apt install whois (whois package)
"""
__all__ = ["Query"]

import subprocess
from shutil import which
from types import SimpleNamespace
from distutils.version import LooseVersion
from .parser import Parser
from .normalise import Normaliser
from ._filecache import filecache, DAY


class _NestedNamespace(SimpleNamespace):
    def __init__(self, dictionary, **kwargs):
        super().__init__(**kwargs)
        for key, value in dictionary.items():
            if isinstance(value, dict):
                self.__setattr__(key, _NestedNamespace(value))
            else:
                self.__setattr__(key, value)


class Query:
    executable: str = which('whois')
    encoding: str = 'utf-8'

    def __setattr__(self, name, value):
        if name in ('executable', 'encoding'):
            super(Query, self).__setattr__(name, value)

    @filecache(DAY*2)
    def _execute(self, args):
        """
        Calls out to subprocess with the passed in args
        This method is normally mocked in tests
        """
        try:
            output = subprocess.check_output(args, timeout=5)  # pragma: no cover
        except subprocess.CalledProcessError as grepexc:
            output = grepexc.output
        except subprocess.TimeoutExpired as t:
            output = "Timed out."
        try:
            output = output.decode(self.encoding)
        except AttributeError:
            output = None
        except:
            try:
                output = output.decode('ISO-8859-1')
            except:
                output = output.decode('latin')
        return output

    def _args(self, domain):
        """
        Builds up the final arguments to pass into subprocess
        whois <domain_name>
        """
        yield self.executable

        # suppress the licence from the output
        yield "-H"

        # The record we want to query
        yield domain

    @staticmethod
    def _preflight(domain):
        """Clean the input."""
        domain = domain.lower()
        domain = domain.replace('http://', '').replace('https://', '').strip()
        domain = domain.split('/', 1)[0]
        domain = domain.replace('www.', '')
        return domain

    def _validate_executable(self):
        """check if desired whois package is available"""
        if not self.executable:
            raise FileNotFoundError('whois is not found. install the whois package')
        ver = self._execute([self.executable, '--version'])
        if ver:
            ver = ver.split('\n')[0]
            if 'illegal option' in ver:
                raise FileNotFoundError('macos native whois not supported. install whois via brew')
            elif 'Version' in ver:
                ver_no = ver.split(' ', 1)[-1]
                if not LooseVersion(ver_no) > LooseVersion("5.5"):
                    raise ValueError("whois version should be >5.5, upgrade whois package")
        else:
            raise ValueError("whois version could not be determined, upgrade whois package")

    def to_dict(self):
        return self.__dict__

    def query(self, domain_name: str, date_as_string: bool = False):
        """
        :param domain_name: the domain name to collect whois information
        :param date_as_string: dates as string if true and not datetime format
        :return: a dict of whois info for the given domain
        """
        self._validate_executable()
        normaliser = Normaliser()

        domain = self._preflight(domain_name)
        args = list(self._args(domain))
        output = self._execute(args)
        if not output:
            result = {
                'domain_name': domain_name,
                'msg': 'fail'
            }
        elif "no match for " in output.lower():
            result = {
                'domain_name': domain_name,
                'msg': 'No match'
            }
        elif "timed out" in output.lower():
            result = {
                'domain_name': domain_name,
                'msg': 'Timeout error'
            }
        else:
            dict_o = Parser()
            result = dict_o.parse(output)
            if not result:
                # could not parse the output for some reason
                # scope to improve the parser
                result = {
                    'domain_name': domain_name,
                    'msg': 'Err parsing',
                    'z_raw': output
                }
            else:
                # final output
                result.update({
                    'msg': 'success',
                    'z_raw': output,
                })

                # normalise the output
                normaliser.date_as_string = date_as_string
                result = normaliser.normalise(result)
                if result['domain_info']['name'] == '':
                    result['domain_info']['name'] = domain

        # return the final result
        return result
