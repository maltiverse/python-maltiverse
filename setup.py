from distutils.core import setup

setup(
    name='maltiverse',
    packages=['maltiverse'],
    version='0.4.1',
    description='API wrapper for Maltiverse',
    author='Antonio Gomez',
    author_email='agm@maltiverse.com',
    url='https://github.com/maltiverse/maltiverse-python',
    download_url='https://github.com/maltiverse/maltiverse-python',
    keywords=['maltiverse', 'API', 'threat intelligence', 'IOC', 'blacklist'],
    classifiers=[],
    requires=['requests']
)
