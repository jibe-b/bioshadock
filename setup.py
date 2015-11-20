import os

from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, 'README.md')) as f:
    README = f.read()
with open(os.path.join(here, 'CHANGES.txt')) as f:
    CHANGES = f.read()

requires = [
    'pyramid',
    'pyramid_chameleon',
    'pyramid_debugtoolbar',
    'pyramid_beaker',
    'waitress',
    'pymongo',
    'PyJWT',
    'cryptography',
    'basicauth',
    'urllib3',
    'redis',
    'docker-py',
    'elasticsearch',
    'GitPython',
    'bcrypt',
    'ldap3',
    'gunicorn',
    'gevent',
    'velruse'
    ]

setup(name='shadock',
      version='0.0',
      description='shadock',
      long_description=README + '\n\n' + CHANGES,
      classifiers=[
        "Programming Language :: Python",
        "Framework :: Pyramid",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Application",
        ],
      author='',
      author_email='',
      url='',
      keywords='web pyramid pylons',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      install_requires=requires,
      tests_require=requires,
      test_suite="shadock",
      entry_points="""\
      [paste.app_factory]
      main = shadock:main
      """,
      )
