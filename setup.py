from setuptools import setup, find_packages

from signal_backup_manager import __version__

install_requires = [

    'protobuf>=3.6.0',
    'cryptography>=2.3.1',
    'requests>=2.18.4',
    'fs>=2.1.1',
    'filetype>=1.0.1',

]

setup(
    name='signal_backup_manager',

    version=__version__,

    description='Manage a Signal Android backup file',

    long_description='',

    author='Yassine El Khadiri',

    packages=find_packages(exclude=['scripts', 'docs', 'tests', 'notebooks']),

    install_requires=install_requires,

    entry_points={
        'console_scripts': [
            'signal-bkp-decrypt=signal_backup_manager.cli:run'
        ]
    }
)
