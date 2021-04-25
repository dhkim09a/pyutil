import setuptools


deps = [
    'sh',
    'matplotlib',
]

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="yautil", # Replace with your own username
    version="0.0.43",
    author="Donghwi Kim",
    author_email="dhkim09@kaist.ac.kr",
    description="Yet Another Python util.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/dhkim09a/pyutil",
    packages=setuptools.find_packages(),
    # classifiers=[
    #     "Programming Language :: Python :: 3",
    #     "License :: OSI Approved :: MIT License",
    #     "Operating System :: OS Independent",
    # ],
    install_requires=deps,
    extras_require={
        'test': deps,
    },
    python_requires='>=3.7',
)
