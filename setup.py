from setuptools import setup, find_packages

setup(
    name="progTek_pwm",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        'flask==3.0.2',
        'flask-sqlalchemy==3.1.1',
        'flask-jwt-extended==4.6.0',
        'pytest==8.0.0',
        'pytest-cov==4.1.0',
    ],
)