"""
Allwhois
---------
Get Whois information for any ccTLD or TLD using the linux/macos
package "whois".

allwhois is a wrapper for the system whois package.

Source code is hosted on `GitHub <https://github.com/marirs/allwhois>`
Contributions are welcome!
"""
from setuptools import find_packages, setup

keywords = [
    'Python 3', 'whois', 'tld', 'domain', 'expiration', 'cctld',
    'domainer', '.com', 'registrar', 'allwhois', 'anywhois'
]

tests_require = [
    'coverage>=4.5',
    'codecov>=2.1.7',
    'pytest>=5.2',
    'pytest-cov>=2.8',
]

extras_require = {
    'tests': tests_require,
}

extras_require['all'] = [req for exts, reqs in extras_require.items()
                         for req in reqs]

setup_requires = [
    'pytest-runner>=5.2',
]

with open('README.md') as f:
    long_description = f.read()


setup(
    name='allwhois',
    version='1.0.0',
    description='Get WHOIS information for a given domain.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Sriram G',
    author_email='marirs@gmail.com',
    license='MIT',
    url='https://github.com/marirs/allwhois/',
    platforms=['posix'],
    zip_safe=False,
    packages=find_packages(),
    include_package_data=True,
    keywords=keywords,
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        "Operating System :: MacOS :: MacOS X",
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Topic :: Internet',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    python_requires='>=3.6',
)
