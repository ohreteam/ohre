from ohre import __version__
from setuptools import setup, find_packages


setup(
    name="ohre",
    version=__version__,
    packages=find_packages(),
    install_requires=[
        "yara-python>=4.5.0",
        "pyyaml>=6.0.2",
        "leb128>=1.0.6",
        "pendulum>=3.0.0"
        ],
    author="https://github.com/ohreteam",
    description="ohre is a analyze and reverse tool of Open HarmonyOS / HarmonyOS NEXT package.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/ohreteam",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: Security",
        "Topic :: Software Development",
        "Topic :: Utilities",
    ],
    python_requires=">=3.9",
)
