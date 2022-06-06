# Secure Group Chat

## Description

A secure group chat application using a PGP-based cryptosystem.

## Getting Started

### Requirements

The following dependencies are required (with recommended versions):

- Java 15

Note: Gradle is used for build automation but need not be installed.

### Installation

Follow these instructions to build the project:

#### Windows

1. ```cd secure-group-chat```

1. ```gradlew build``` 

#### Unix

1. ```cd secure-group-chat```

1. ```./gradlew build``` 

## Usage

Once the project is built, run the following commands to:

1. Run the certificate authority
1. Run the server
1. Run 3 separate clients

#### Windows

1. ```run ca```
1. ```run server```
1. ```run client``` (in 3 separate terminals)

#### Unix

1. ```./run ca```
1. ```./run server```
1. ```./run client``` (in 3 separate terminals)

### Clean

To remove build-related artefacts and files, run:

#### Windows

1. ```gradlew clean```

#### Unix

1. ```./gradlew clean```

## Authors

- Jaron Cohen
- Bailey Green
- Carl Combrinck
