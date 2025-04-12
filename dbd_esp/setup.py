from setuptools import setup, find_packages

with open("requirements.txt") as f:
    requirements = f.read().splitlines()

setup(
    name="dbd_esp",
    version="1.0.0",
    packages=find_packages(),
    install_requires=requirements,
    python_requires=">=3.8",
    author="Cline",
    description="Dead by Daylight ESP in Python",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: Microsoft :: Windows",
        "Topic :: Games/Entertainment",
    ],
)
