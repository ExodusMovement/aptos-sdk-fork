# SDK Aptos

## Installation

##### For use in Node.js or a web application

```ts
pnpm install aptos
```

### Testing

To run the full SDK tests, From the [root](https://github.com/aptos-labs/aptos-core/tree/main/ecosystem/typescript/sdk) of this package, run:

```ts
pnpm test

npx jest -- <path/to/file.test.ts>
```

To use the local build in a local project:

```ts
// run from the root of this package
pnpm build
// run on your local project
pnpm add PATH_TO_LOCAL_SDK_PACKAGE
```
