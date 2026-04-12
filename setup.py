# setup.py
from setuptools import setup, find_packages

setup(
    name="cagoule-pass",
    version="1.0.0",
    description="Gestionnaire de mots de passe chiffré avec CAGOULE",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="Slim Issa",
    author_email="slim.issa@example.com",
    license="MIT",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "cagoule>=1.5.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "pytest-timeout>=2.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "cagoule-pass=cagoule_pass.cli:main",
        ],
    },
    python_requires=">=3.9",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: End Users/Desktop",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Topic :: Security :: Cryptography",
        "Topic :: Utilities",
    ],
    keywords="password, manager, encryption, cagoule, security, cli",
    project_urls={
        "Homepage": "https://github.com/slimissa/CAGOULE",
        "Repository": "https://github.com/slimissa/cagoule-pass",
    },
)