
from setuptools import setup, find_packages


setup(
    name='snort_web_master',
    version='1.0.0.8',
    license='MoCorp',
    readme="README.md",
    author="meir dahan",
    author_email='1dahanmeir1@gmail.com',
    packages=find_packages('snort_web_master'),
    package_dir={'': 'snort_web_master'},
    url='https://github.com/mosheovadi1/snort-web-master',
    keywords='snort3 django',
    include_package_data=True,
    install_requires=[
          'django',
          'django-auth-ldap3-ad',
          'django-object-actions',
          'dpkt',
          'django-advanced-filters',
          'suricataparser',
          'django-import-export',
          "psycopg2-binary==2.9.1",
          "gunicorn==20.1.0",
          "django-cors-headers"
      ],

)

"""git add .
git commit -m "updatas"
git push
py setup.py sdist
py -m twine upload dist/*"""