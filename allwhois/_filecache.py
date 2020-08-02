"""
cache raw outputs to file
"""
import collections as _collections
import datetime as _datetime
import functools as _functools
import inspect as _inspect
import os as _os
import pickle as _pickle
import codecs as _codecs
import shelve as _shelve
import sys as _sys
import time as _time
import traceback as _traceback
import types
import atexit

_retval = _collections.namedtuple('_retval', 'timesig data')
_SRC_DIR = _os.path.dirname(_os.path.abspath(__file__))
_CACHE_STORE = '.cache'

SECOND = 1
MINUTE = 60 * SECOND
HOUR = 60 * MINUTE
DAY = 24 * HOUR
WEEK = 7 * DAY
MONTH = 30 * DAY
YEAR = 365 * DAY
FOREVER = None

OPEN_DBS = dict()


def _get_cache_name(function):
    """
    returns a name for the module's cache db.
    """
    module_name = _inspect.getfile(function)
    cache_name = _os.path.basename(_os.path.splitext(module_name)[0])
    if not _os.path.exists(_CACHE_STORE):
        _os.makedirs(_CACHE_STORE)

    # fix for '<string>' or '<stdin>' in exec or interpreter usage.
    cache_name = cache_name.replace('<', '').replace('>', '')
    cache_name = _os.path.join(_CACHE_STORE, f'{cache_name}.cache')

    return cache_name


def _log_error(error_str):
    try:
        error_log_fname = _os.path.join(_SRC_DIR, 'filecache.err.log')
        if _os.path.isfile(error_log_fname):
            fhand = open(error_log_fname, 'a')
        else:
            fhand = open(error_log_fname, 'w')
        fhand.write('[%s] %s\r\n' % (_datetime.datetime.now().isoformat(), error_str))
        fhand.close()
    except Exception:
        pass


def _args_key(function, args, kwargs):
    arguments = (args, kwargs)
    # Check if you have a valid, cached answer, and return it.
    if _sys.version_info[0] == 2:
        arguments_pickle = _pickle.dumps(arguments)
    else:
        # NOTE: protocol=0 so it's ascii, this is crucial for py3k
        #       because shelve only works with proper strings.
        #       Otherwise, we'd get an exception because
        #       function.__name__ is str but dumps returns bytes.
        arguments_pickle = _codecs.encode(_pickle.dumps(arguments, protocol=0), "base64").decode()

    key = function.__name__ + arguments_pickle
    return key


def filecache(seconds_of_validity=None, fail_silently=False):
    """
    filecache is called and the decorator should be returned.
    """

    def filecache_decorator(function):
        @_functools.wraps(function)
        def function_with_cache(*args, **kwargs):
            key = None
            try:
                key = _args_key(function, args, kwargs)

                if key in function._db:
                    rv = function._db[key]
                    if seconds_of_validity is None or _time.time() - rv.timesig < seconds_of_validity:
                        return rv.data
            except Exception:
                # in any case of failure, don't let filecache break the program
                error_str = _traceback.format_exc()
                _log_error(error_str)
                if not fail_silently:
                    raise

            retval = function(*args, **kwargs)

            # store in cache
            # NOTE: no need to _db.sync() because there was no mutation
            # NOTE: it's importatnt to do _db.sync() because otherwise the cache doesn't survive Ctrl-Break!
            try:
                function._db[key] = _retval(_time.time(), retval)
                function._db.sync()
            except Exception:
                # in any case of failure, don't let filecache break the program
                error_str = _traceback.format_exc()
                _log_error(error_str)
                if not fail_silently:
                    raise

            return retval

        # make sure cache is loaded
        if not hasattr(function, '_db'):
            cache_name = _get_cache_name(function)
            if cache_name in OPEN_DBS:
                function._db = OPEN_DBS[cache_name]
            else:
                function._db = _shelve.open(cache_name)
                OPEN_DBS[cache_name] = function._db
                atexit.register(function._db.close)

            function_with_cache._db = function._db

        return function_with_cache

    if isinstance(seconds_of_validity, types.FunctionType):
        # support when used as '@filecache.filecache' instead of '@filecache.filecache()'
        func = seconds_of_validity
        seconds_of_validity = None
        return filecache_decorator(func)

    return filecache_decorator

