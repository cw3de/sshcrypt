# sshcrypt

Encrypt and decrypt files using sshkeys from ssh-agent 

## Introduction

While you can't get the private key from the ssh-agent, we can use the ssh-agent to get a signature from a random salt, which can be used as a secret key for encryption and decryption.

## Usage

Use `sshcrypt` with no args to get a help on the usage.
