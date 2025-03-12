# Encrypted Repository Manager

Makes encrypted repositories of information.
Although this is a public it is not especially intended to be easily usable by the general public,
more so by those who know about it and have been introduced to it.

If you are using this for the first time you will need to create a master_password_hash. check_master_password()
shows more or less how to do this - write the digest.finalize() to a binary file i.e. "wb" mode. Just interactively use the python interpreter to do this.

## Usage

```sh
python manager.py
```