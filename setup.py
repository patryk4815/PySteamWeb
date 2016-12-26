from setuptools import setup, find_packages

setup(
    name='PySteamWeb',
    version='1.2.1',
    packages=find_packages(include=['pysteamweb*']),
    url='https://github.com/patryk4815/PySteamWeb',
    license='MIT',
    author='Patryk Sondej',
    author_email='patryk.sondej@gmail.com',
    description='python3 steam web login async',
    keywords=['python3', 'steam', 'login', 'api', 'async', 'aiohttp', 'asyncio', 'asynchronous'],
    platforms='Posix; MacOS X; Windows',
    install_requires=[
        'pycrypto>=2.6',
        'aiohttp==1.1.6',
        'beautifulsoup4>=4.4',
    ]
)
