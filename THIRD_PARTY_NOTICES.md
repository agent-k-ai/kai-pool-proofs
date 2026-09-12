# Third-party notices

This repository reuses source files from the Apache-2.0 licensed
`alpha-tech-org/agent-kai-prediction-market` project and depends on the
MIT licensed runtime libraries listed below. Full license texts are
provided for every third-party component.

## Reused source files

The files listed in `provenance/SOURCE-EXTRACTION-INVENTORY.json` are
derived from `alpha-tech-org/agent-kai-prediction-market` at commit
`00f4ec0effe091216896e1ee44d733e57ebfe1e6` (release-01.09.06b).

```
Copyright 2026 Alpha Tech Organization

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```

The generic Merkle Patricia trie verification in
`packages/volume-proof/src/ethereum-state-proof.ts` is a TypeScript
port of the MIT licensed Optimism trie libraries (RLP and Ethereum
state-proof verification), pinned in the parent project at
`29bec1e4d0e9ab90f9132e418cdc2b0f9756483c`.

## Runtime dependencies

| Dependency | Version | License |
| ---------- | ------- | ------- |
| viem       | 2.56.1  | MIT     |
| zod        | 4.5.4   | MIT     |

### viem (MIT)

```
MIT License

Copyright (c) 2023 Wevm

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### zod (MIT)

```
MIT License

Copyright (c) 2020 - 2024 Colin McDonnell

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Development dependencies

Development dependencies (TypeScript, vitest, eslint and their transitive
tree) are pinned in `pnpm-lock.yaml`. Their licenses are checked at export
time by the allowlisted license scan. No development dependency ships in
the published package.