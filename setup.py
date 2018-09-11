#! /usr/bin/env python3

from setuptools import setup, find_packages

version = {}
with open('cmsmap/version.py') as f:
    exec(f.read(), version)

setup(
    name='cmsmap',
    version=version['__version__'],
    description='CMS vulnerability scanner',
    author='Mike Manzotti',
    # author_email='',
    url='https://github.com/Dionach/CMSmap',
    license='GPL',
    packages=find_packages(),
    package_data={'': ['*.conf', '*.txt', '*.zip']},
    entry_points={'console_scripts': [
        'cmsmap = cmsmap.main:main',
    ]},
    install_requires=[
        #'package>=version'
    ])
