from setuptools import setup, find_packages

setup(
    name='profile-translator-blocklist',
    version='0.4.0',
    author='François De Keersmaeker',
    author_email='francois.dekeersmaeker@uclouvain.be',
    description='Translate IoT YAML profiles to NFTables / NFQueue files for a block-list firewall.',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/smart-home-network-security/profile-translator-blocklist',
    license='GPLv3+',
    packages=find_packages(),
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Operating System :: OS Independent'
    ],
    python_requires='>=3.8',
    install_requires=[
        "PyYAML",
        "Jinja2",
        "pyyaml-loaders"
    ],
    package_data={
        'profile_translator_blocklist': ['templates/*']
    },
    include_package_data=True
)
