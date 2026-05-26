import { createRequire } from "node:module";

type PackageJson = {
  version: string;
};

export const PACKAGE_VERSION = (createRequire(import.meta.url)("../package.json") as PackageJson).version;
