from distutils.core import setup

setup(
    name='maltiverse',
    packages=['maltiverse'],
    version='1.0.0',
    license='MIT',
    description='Python API wrapper for Maltiverse',
    author='Antonio Gomez',
    author_email='agm@maltiverse.com',
    url='https://github.com/maltiverse/maltiverse-python',
    download_url='https://github.com/maltiverse/python-maltiverse/archive/1.0.0.tar.gz',
    keywords=['maltiverse', 'API', 'threat intelligence', 'IoC', 'blacklist', 'search engine'],
    install_requires=['requests', 'PyJWT'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3', 
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
)
