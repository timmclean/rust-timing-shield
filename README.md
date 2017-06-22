# rust-timing-shield

Project home page: https://www.chosenplaintext.ca/open-source/rust-timing-shield/

`rust-timing-shield` provides Rust programs with comprehensive protection from
timing attacks.

One of the fundamental challenges of writing software that operates on sensitive information
is preventing *timing leaks*. A timing leak is when there exists a relationship between the
values of secret variables in your program and the execution time of your code or other code
running on the same hardware. Attackers who are aware of this relationship can use a
high-resolution timer to learn secret information that they would not normally be able to
access (e.g. extract an SSL key from a web server).

To prevent timing leaks in cryptography code, it is best practice to write code that is
*constant-time*. For a full background on writing constant-time code, see [A beginner's guide
to constant-time
cryptography](https://www.chosenplaintext.ca/articles/beginners-guide-constant-time-cryptography.html).

`rust-timing-shield` is a framework for writing code without timing leaks.
See the [Getting Started
page](https://www.chosenplaintext.ca/open-source/rust-timing-shield/getting-started) for more
information.

## Reporting security vulnerabilities

Please visit [the Security
page](https://www.chosenplaintext.ca/open-source/rust-timing-shield/security)
for more information.

## License

The MIT License (MIT)

Copyright (c) 2017 Tim McLean

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
