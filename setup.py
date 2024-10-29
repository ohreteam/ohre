from ohre import __version__
from setuptools import setup, find_packages

with open("requirements.txt", "r") as fp:
    install_requires = fp.read().splitlines()

setup(
    name="ohre",
    version=__version__,
    packages=find_packages(),
    install_requires=install_requires,
    author="https://github.com/ohreteam",
    description="ohre is a analyze and reverse tool of Open HarmonyOS / HarmonyOS NEXT package.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/ohreteam",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: AGPL-3.0 License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: Security",
        "Topic :: Software Development",
        "Topic :: Utilities",
        "Topic :: HarmonyOS"
    ],
    python_requires=">=3.9",
)
