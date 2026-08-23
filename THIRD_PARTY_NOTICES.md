# Third-party notices

Web App Security Skill includes a generated JavaScript parser runtime built from the component
below. The generated file is used so npm, verified archive, Claude plugin, Codex Skill and GitHub
Action installations run the same parser without downloading dependencies at audit time.

## @babel/parser 7.28.4

- Project: Babel parser
- Source: https://github.com/babel/babel/tree/v7.28.4/packages/babel-parser
- Package: https://www.npmjs.com/package/@babel/parser/v/7.28.4
- License: MIT
- Copyright: Babel contributors

Build input integrity, generated SHA-256 and generator version are recorded in
`scripts/vendor/js-ts-parser.manifest.json`.

Copyright (c) 2014-present Sebastian McKenzie and other contributors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute,
sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## esbuild

esbuild is a development-only build tool used to create the parser runtime. It is not included in
the runtime bundle. Its exact version and registry integrity are recorded in `package-lock.json`.
