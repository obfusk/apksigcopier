from pathlib import Path
import setuptools

from apksigcopier import __version__

info = Path(__file__).with_name("README.md").read_text(encoding = "utf8")

setuptools.setup(
    name              = "apksigcopier",
    url               = "https://github.com/obfusk/apksigcopier",
    description       = "copy/extract/patch android apk signatures & compare apks",
    long_description  = info,
    long_description_content_type = "text/markdown",
    version           = __version__,
    author            = "FC Stegerman",
    author_email      = "flx@obfusk.net",
    license           = "GPLv3+",
    classifiers       = [
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Telecommunications Industry",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX :: Linux",
        "Operating System :: POSIX",
        "Operating System :: Unix",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
      # "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Topic :: Software Development",
        "Topic :: Utilities",
    ],
    keywords          = "android apk reproducible signing compare",
    entry_points      = dict(console_scripts = ["apksigcopier = apksigcopier:main"]),
    packages          = ["apksigcopier"],
    package_data      = dict(apksigcopier = ["py.typed"]),
    python_requires   = ">=3.7",
    install_requires  = ["click>=6.0"],
)
