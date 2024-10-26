# OHRE
<p>
<a href="https://github.com/kokifish/ohre/star"><img alt="stars" src="https://img.shields.io/github/stars/kokifish/ohre?style=social"></a>
<a href="https://github.com/kokifish/ohre"><img alt="watchers" src="https://img.shields.io/github/watchers/kokifish/ohre?style=social"></a> 
<a href="https://github.com/kokifish/ohre"><img alt="updated time" src="https://badges.pufler.dev/updated/kokifish/ohre"></a>
<a href="https://github.com/kokifish/ohre"><img alt="last-commit" src="https://img.shields.io/github/last-commit/kokifish/ohre"></a>
<a href="https://github.com/kokifish/ohre"><img alt="created time" src="https://badges.pufler.dev/created/kokifish/ohre"></a>
<a href="https://github.com/kokifish/ohre"><img alt="visits" src="https://badges.pufler.dev/visits/kokifish/ohre"></a>
<a href="https://github.com/kokifish/ohre"><img alt="license" src="https://img.shields.io/github/license/kokifish/ohre"></a>
<a href="https://github.com/kokifish/ohre/graphs/commit-activity"><img alt="maintained" src="https://img.shields.io/badge/Maintained%3F-yes-green.svg"></a>
</p>

A **O**pen **H**armonyOS app/hap package analyze and **RE**verse tool. Maybe pronounced like "ōli".

## Features

OHRE is a full python(python3) tool to play with HarmonyOS files.
- pack.json
- handle .app and .hap
- resources.index
- white/black list of file names in specific path

## Installation

- Dependency: yara-python

### Linux/MacOS
```bash
pip install yara-python
# install as a python package locally
pip install -e . # in same dolder as setup.py
python ohre_demo.py xxx.hap # run demo with HarmonyOS hap
python ohre_demo.py xxx.app # run demo with HarmonyOS app
```

## How to Use
`ohre_demo.py` is a demo that shows almost all usages. Check it and then maybe check the wiki.

## Contacts
Please new an issue or make a MR.