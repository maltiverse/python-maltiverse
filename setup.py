from setuptools import setup

setup(
    name="maltiverse",
    packages=["maltiverse"],
    version="1.2.10",
    license="MIT",
    description="Python API wrapper for Maltiverse",
    author="Antonio Gomez",
    author_email="agm@maltiverse.com",
    url="https://github.com/maltiverse/maltiverse-python",
    download_url="https://github.com/maltiverse/python-maltiverse/archive/master.zip",
    keywords=[
        "maltiverse",
        "API",
        "threat intelligence",
        "IoC",
        "blacklist",
        "search engine",
    ],
    install_requires=["requests", "PyJWT"],
    python_requires=">=3.11",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Build Tools",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
)
