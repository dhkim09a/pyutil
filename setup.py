import setuptools
import os

# borrowed from https://stackoverflow.com/a/36693250
def package_files(directory):
    paths = []
    for (path, directories, filenames) in os.walk(directory):
        for filename in filenames:
            paths.append(os.path.join('..', path, filename))
    return paths


deps = [
    'sh',
    'matplotlib',
    'typing_extensions',
    'keyring',
]

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="yautil", # Replace with your own username
    version="0.0.68",
    author="Donghwi Kim",
    author_email="dh.tony.kim@samsung.com",
    description="Yet Another Python util.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.sec.samsung.net/dh-tony-kim/pyutil",
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
    package_data={'': package_files('yautil/mountutil/yaffs2utils-0.2.9')},
    python_requires='>=3.11',
)
