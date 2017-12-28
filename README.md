# IRMA API common

This library contains the basic functionality of IRMA, in particular:

* Parsing `irma_configuration` folders, containing [scheme manager](https://credentials.github.io/docs/irma.html#scheme-managers) files (i.e., descriptions of scheme managers, issuers, and credential types, as well as Idemix public and possibly private keys; [demo example](https://github.com/credentials/irma-demo-schememanager)).
* Our Idemix implementation, handling the cryptographic details of issuing and verification of attributes.
* Parsing and writing IRMA [metadata attributes](https://credentials.github.io/docs/irma.html#the-metadata-attribute). Together with the credential and issuer descriptions from the `irma_configuration` folder, these give meaning to the bare Idemix attributes.
* Classes whose instances when JSON-serialized serve as the messages in the IRMA protocol.

For example, this library is used in [`irma_api_server`](https://github.com/privacybydesign/irma_api_server), which issues and verifies IRMA attributes, and [`irma_keyshare_server`](https://github.com/privacybydesign/irma_keyshare_server), which verifies user PIN codes.

When compared to our Go codebase, this library roughly corresponds to [`gabi`](https://github.com/mhe/gabi) and the `irma` package of [`irmago`](https://github.com/privacybydesign/irmago).

## Important classes

* `DescriptionStore` gives access to the parsed `irma_configuration` files, except for the Idemix public and private keys.
* `IdemixKeyStore` gives access to Idemix public and private keys from the `irma_configuration` folder.
* `Attributes` gives access to the contents of the metadata attribute, as well as the other attributes of a credential instance.
* `IdemixCredential` represent Idemix credential instances and can be used to create IRMA disclosure proofs.

## Building using Gradle

Install gradle if you don't already have it, and run

    gradle install

to install the library to your local repository. Alternatively, you can run

    gradle build

to just build the library.

## Running unit tests

In order to use the included unit tests, use

    gradle test

## Eclipse development files

You can run

    gradle eclipse

to create the required files for importing the project into Eclipse.

## Deprecated libraries

This library contains all of the classes from the now deprecated libraries `credentials_api` and `credentials_idemix`, which can still be seen [here](https://github.com/credentials/credentials_api) and [here](https://github.com/credentials/credentials_idemix) respectively.
