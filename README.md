# NTRUEncrypt library for Rust #

[![Build Status](https://travis-ci.org/FractalGlobal/ntru-rs.svg?branch=master)](https://travis-ci.org/FractalGlobal/ntru-rs)
[![Build status](https://ci.appveyor.com/api/projects/status/w352flnvc7psujnf?svg=true)](https://ci.appveyor.com/project/Razican/ntru-rs)
[![Coverage Status](https://coveralls.io/repos/FractalGlobal/ntru-rs/badge.svg?branch=master&service=github)](https://coveralls.io/github/FractalGlobal/ntru-rs?branch=master)
[![Crates.io](https://meritbadge.herokuapp.com/ntru)](https://crates.io/crates/ntru)

This library implements an interface with
*[libntru](https://tbuktu.github.io/ntru/)* C library. It is currently under
development, but can be used to encrypt and decrypt data. The documentation can
be found [here](http://fractal.global/ntru-rs). This library was selected due to
its better performance comparing to the reference NTRUEncrypt implementation.

# License #

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version. You can also redistribute it and/or modify it under the terms of the
3-clause BSD license, since this library is double licensed.
