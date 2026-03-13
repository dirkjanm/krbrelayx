from setuptools import setup, find_packages

setup(
    name='krbrelayx',
    version='1.0.0',
    author='Dirk-jan Mollema',
    author_email='example@example.com',
    url='https://github.com/dirkjanm/krbrelayx',
    description='Tools for performing Kerberos relay attacks',
    long_description='This package includes several tools that can be used to perform Kerberos relay attacks, including attacks against Active Directory Certificate Services (AD CS)',
    license='MIT',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'impacket>=0.9.21',  # assuming krbrelayx relies on Impacket, similar to other tools in the same domain
        'ldap3',
        'flask',  # only include if the project has a web component or similar functionality requiring flask
        'dnspython',
        'setuptools',
        'pycryptodome',
        # add other dependencies as necessary
    ],
    scripts=[
        'addspn.py',
        'dnstool.py',
        'krbrelayx.py',
        'printerbug.py',
        # list other scripts that should be directly executable from the command line
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
    ],
    python_requires='>=3.6',
    keywords='kerberos relay attack security',
)
