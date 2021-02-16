import setuptools

with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

setuptools.setup(
    name='pritunl-wireguard-client',
    version='0.0.1',
    author='supernbo@gmail.com',
    author_email='supernbo@gmail.com',
    description='pritunl wireguard configuration retriever',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/superbo/pritunl-wireguard-client',
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    packages=[
        'pritunl_wireguard_client',
        'pritunl_wireguard_client.utils'
    ],
    install_requires=[
        'pynacl',
        'cryptography',
        'requests',
        'segno'
    ],
    scripts=['bin/pritunl-wireguard-client'],
    python_requires='>=3.6'
)
