from pathlib import Path
import setuptools

# from apksigcopier import __version__                         # FIXME
__version__ = "0.3.0"

info = Path(__file__).with_name("README.md").read_text(encoding = "utf8")

setuptools.setup(
    name              = "apksigcopier",
    url               = "https://github.com/obfusk/apksigcopier",
    description       = "copy/extract/patch apk signatures",
    long_description  = info,
    long_description_content_type = "text/markdown",
    version           = __version__,
    author            = "Felix C. Stegerman",
    author_email      = "flx@obfusk.net",
    license           = "GPLv3+",
    classifiers       = [
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
      # "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: Implementation :: CPython",
        "Topic :: Software Development",
        "Topic :: Utilities",
    ],
    keywords          = "android apk reproducible signing",
    py_modules        = ["apksigcopier"],
    entry_points      = dict(console_scripts = ["apksigcopier = apksigcopier:main"]),
    python_requires   = ">=3.5",
    install_requires  = ["click>=6.0"],
)
