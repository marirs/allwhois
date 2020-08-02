from distutils.core import setup

keywords = [
    'Python 3', 'whois', 'tld', 'domain', 'expiration', 'cctld',
    'domainer', '.com', 'registrar', 'allwhois', 'anywhois'
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
    packages=['allwhois'],
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
