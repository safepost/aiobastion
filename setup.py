import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="aiobastion", # Replace with your own username
    version="0.0.1",
    author="Gautier Leveille",
    author_email="gautier.leveille@labanquepostale.fr",
    description="Manage your Cyberark implementation",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/labanquepostale/aiobastion",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta"
    ],
    python_requires='>=3.7',
    install_requires=[
        'aiohttp',
        'pyyaml',
    ]
)
