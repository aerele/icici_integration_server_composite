from setuptools import setup, find_packages

with open('requirements.txt') as f:
	install_requires = f.read().strip().split('\n')


# get version from __version__ variable in icici_integration_server_composite/__init__.py
from icici_integration_server_composite import __version__ as version

setup(
	name='icici_integration_server_composite',
	version=version,
	description='Implementation of ICICI Integration Server Composite API',
	author='Aerele',
	author_email='admin@aerele.in',
	packages=find_packages(),
	zip_safe=False,
	include_package_data=True,
	install_requires=install_requires
)