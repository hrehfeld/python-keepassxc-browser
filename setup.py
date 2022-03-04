from setuptools import find_packages, setup

setup(
    name='keepassxc-browser',
    version='0.1.8',
    packages=find_packages(),
    install_requires=['pysodium', 'pywin32; platform_system == "Windows"'],
    description='Access the KeepassXC Browser API from python',
    url='https://github.com/hrehfeld/python-keepassxc-browser',
    author='Hauke Rehfeld',
    author_email='pypi.org@haukerehfeld.de',
    license='AGPL-3.0',
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries",
    ],
)
