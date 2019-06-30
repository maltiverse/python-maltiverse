from distutils.core import setup

setup(
    name='maltiverse',
    packages=['maltiverse'],
    version='0.7.4',
    description='API wrapper for Maltiverse',
    author='Antonio Gomez',
    author_email='agm@maltiverse.com',
    url='https://github.com/maltiverse/maltiverse-python',
    download_url='https://github.com/maltiverse/maltiverse-python',
    keywords=['maltiverse', 'API', 'threat intelligence', 'IoC', 'blacklist', 'search engine'],
    classifiers=[],
    requires=['hashlib', 'requests', 'PyJWT', 'urllib', 'base64', 'json', 'unittest', 'time']
)
