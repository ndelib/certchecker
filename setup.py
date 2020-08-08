import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="certchecker-ndelib",
    version="0.0.1",
    author="Nelson",
    author_email="nelsonwork100@example.com",
    description="A Python package to analyse TLS certificates and help troubleshoot issues",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ndelib/certchecker",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)