# Secure Group Chat

## Description

A secure group chat application using a PGP-based cryptosystem.

## Getting Started

### Requirements

The following dependencies are required (with recommended versions):

- Java 18 
- Maven 3.8.5

### Installation

Follow these instructions to build the project:

1. ```cd securechat```

1. ```mvn package```

### Clean

To remove build-related artefacts and files, run:
1. ```mvn clean```

## Usage

Once the project is built, run the following command to run the server:

1. ```java -cp target/securechat-1.0-SNAPSHOT.jar com.nis.Server 1234```

In 3 separate terminals, execute the following command to run clients:

2. ```java -cp target/securechat-1.0-SNAPSHOT.jar com.nis.Client localhost 1234```

## Authors


