try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(
    name='PySteamWeb',
    version='0.1',
    packages=['pysteamweb'],
    url='https://github.com/patryk4815/PySteamWeb',
    license='MIT',
    author='Patryk Sondej',
    author_email='patryk.sondej@gmail.com',
    description='python3 steam web login',
    keywords=['python3', 'steam', 'login', 'api'],
    platforms='Posix; MacOS X; Windows',
    install_requires=[
        'pycrypto>=2.6',
        'requests>=2.5',
    ]
)
