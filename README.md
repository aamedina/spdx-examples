# net.wikipunk/spdx-examples
Querying graphs of SPDX documents with Datomic

## dev
Set GITHUB_TOKEN in your environment to a personal access token with
read-only public repository permissions so you can download public
SPDX documents from the GitHub Dependency Graph over REST API.

``` shell
export GITHUB_TOKEN=YOUR_GITHUB_TOKEN
```

``` shell
clojure -A:dev
```

``` clojure
(reset)
```

This will download the SBOMs configured in the SbomGraph component
using the `dev/system.edn` component system map. If you want to add
different SBOMs, you can edit this config file with [owner repo] pairs
and just call `(reset)` again in the REPL.

## License

Copyright (c) 2023 Adrian Medina

Permission to use, copy, modify, and/or distribute this software for
any purpose with or without fee is hereby granted, provided that the
above copyright notice and this permission notice appear in all
copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
