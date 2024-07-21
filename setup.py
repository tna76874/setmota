#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
from setuptools import find_packages, setup

import setmota

setup(
    name='setmota',
    version=setmota.__version__,
    description='setmota',
    url='https://github.com/tna76874/setmota.git',
    author='lmh',
    author_email='',
    license='BSD 2-clause',
    packages=find_packages(),
    install_requires=[
        "numpy",
        "pandas",
        "datetime",
        "matplotlib",
        "requests",
        "openpyxl",
    ],
    classifiers=[
        'Development Status :: 1 - Planning',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: BSD License',  
        'Operating System :: POSIX :: Linux',        
        'Programming Language :: Python :: 3.9',
    ],
    python_requires=">=3.8",
    entry_points={
        'console_scripts': [
            'setmota = setmota.cli:main',
        ],
    },
)