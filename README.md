# WhatAmIThinking-HostUtil

hostname/address parsers/validators/utils for handling user inputs which could be either.

## Overview

There are some cases where you want to get a **host** input from the user and want to allow them to enter either a hostname or an ip address. This package seeks to help validate that input and determine which type (address or hostname) was likely entered.

Additionally, there are times when you need to determine if the given host points to the local machine or not. This package exposes a function to check this and check it definitively, across all network interfaces if need be.

Documentation consists of what you see here and the docs in the code.
