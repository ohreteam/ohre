from setuptools import setup, find_packages

setup(
    name="ohre",
    version="0.0.1",
    packages=find_packages(),
    install_requires=[
        "yara-python",
    ],
    author="kokifish",
    author_email="k0k1fish@outlook.com",
    description="open harmony hap package reverse tool",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/kokifish/ohre",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: AGPL-3.0 License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)
